import { SSHConnectionConfig } from '../types';
import {
  SSH_MSG_KEXINIT,
  SSH_MSG_NEWKEYS,
  SSH_MSG_KEX_ECDH_REPLY,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_SUCCESS,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_DISCONNECT,
  SSH_MSG_IGNORE,
  SSH_MSG_DEBUG
} from '../types';
import { SSHTransport } from '../ssh/transport';
import { SSHPacketParser, SSHPacketBuilder } from '../ssh/packet';
import { KEXInitBuilder } from '../ssh/kex';
import { ECDHKeyExchange } from '../ssh/kex-ecdh';
import { KeyDerivation } from '../ssh/keys';
import { SSHAESGCMCipher } from '../ssh/crypto';
import { SSHAuth } from '../ssh/auth';
import { SSHChannel } from '../ssh/channel';

export class SSHSession {
  private ws: WebSocket;
  private socket: any;
  private config: SSHConnectionConfig;

  private transport: SSHTransport;
  private packetParser: SSHPacketParser;
  private channel: SSHChannel;
  private encryptCipher: SSHAESGCMCipher | null = null;
  private decryptCipher: SSHAESGCMCipher | null = null;
  private derivedKeys: any = null;

  private seqNumSend: number = 0;
  private seqNumRecv: number = 0;
  private sessionID: Uint8Array | null = null;

  private kexInitLocal: Uint8Array | null = null;
  private kexInitRemote: Uint8Array | null = null;

  private ecdhKeyPair!: CryptoKeyPair;
  private ecdhRawPublicKey!: Uint8Array;

  private state: 'connecting' | 'version' | 'kex' | 'auth' | 'shell' | 'ready'
    = 'connecting';

  constructor(ws: WebSocket, socket: any, config: SSHConnectionConfig) {
    console.log('[SSH] Constructor called');
    this.ws = ws;
    this.socket = socket;
    this.config = config;
    this.transport = new SSHTransport();
    this.packetParser = new SSHPacketParser();
    this.channel = new SSHChannel();
  }

  async startHandshake(): Promise<void> {
    console.log('[SSH] Starting handshake, current state:', this.state);
    this.ws.send(JSON.stringify({ type: 'status', message: '正在交换版本信息...' }));
    this.state = 'version';
    console.log('[SSH] State changed to: version');
    
    const writer = this.socket.writable.getWriter();
    const versionStr = 'SSH-2.0-CloudSSH_1.0\r\n';
    console.log('[SSH] Sending version string:', versionStr.trim());
    await writer.write(new TextEncoder().encode(versionStr));
    writer.releaseLock();
    console.log('[SSH] Version string sent');
    
    this.startReading();
  }

  private async startReading(): Promise<void> {
    console.log('[SSH] Starting read loop');
    const reader = this.socket.readable.getReader();
    const decoder = new TextDecoder();

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          console.log('[SSH] TCP stream ended');
          break;
        }

        console.log('[SSH] Received data, state:', this.state, 'bytes:', value.length);

        if (this.state === 'version') {
          const versionStr = decoder.decode(value);
          console.log('[SSH] Server version:', versionStr.trim());
          if (this.transport.handleVersionExchange(versionStr)) {
            console.log('[SSH] Version exchange complete');
            this.ws.send(JSON.stringify({ type: 'status', message: '版本交换完成，正在密钥协商...' }));
            this.state = 'kex';
            console.log('[SSH] State changed to: kex');
            await this.startKEX();
          }
        } else {
          try {
            this.packetParser.feed(value);
            await this.processPackets();
          } catch (pktError) {
            const pktErrMsg = pktError instanceof Error ? pktError.message : String(pktError);
            console.error('[SSH] Packet processing error:', pktErrMsg);
            throw pktError;
          }
        }
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      const errStack = error instanceof Error ? error.stack : '';
      console.error('[SSH] Read loop error:', errMsg, errStack);
      try {
        this.ws.send(JSON.stringify({
          type: 'error',
          message: 'SSH 连接断开: ' + errMsg
        }));
      } catch {}
    }
  }

  private async startKEX(): Promise<void> {
    console.log('[KEX] Starting key exchange');
    this.kexInitLocal = KEXInitBuilder.build();
    console.log('[KEX] Built KEXINIT, length:', this.kexInitLocal.length);
    
    const packet = await SSHPacketBuilder.build(
      this.kexInitLocal, 8, null, this.seqNumSend++
    );
    console.log('[KEX] Sending KEXINIT packet, length:', packet.length);
    await this.writeSocket(packet);
    console.log('[KEX] KEXINIT sent');

    console.log('[KEX] Generating ECDH key pair...');
    this.ecdhKeyPair = await ECDHKeyExchange.generateKeyPair();
    console.log('[KEX] ECDH key pair generated');
    
    this.ecdhRawPublicKey = await ECDHKeyExchange.exportRawPublicKey(
      this.ecdhKeyPair
    );
    console.log('[KEX] Raw public key exported, length:', this.ecdhRawPublicKey.length);

    const ecdhInit = ECDHKeyExchange.buildInit(this.ecdhRawPublicKey);
    const ecdhPacket = await SSHPacketBuilder.build(
      ecdhInit, 8, null, this.seqNumSend++
    );
    console.log('[KEX] Sending ECDH_INIT packet, length:', ecdhPacket.length);
    await this.writeSocket(ecdhPacket);
    console.log('[KEX] ECDH_INIT sent, waiting for server reply...');
  }

  private async writeSocket(data: Uint8Array): Promise<void> {
    const writer = this.socket.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

  private async processPackets(): Promise<void> {
    const blockSize = this.decryptCipher ? 16 : 8;

    while (true) {
      const packet = await this.packetParser.nextPacket(
        blockSize,
        this.decryptCipher
          ? (data, seq, aad) => this.decryptCipher!.decrypt(data, seq, aad)
          : (data) => data,
        !!this.decryptCipher
      );

      if (!packet) break;

      const msgType = packet.payload[0];
      console.log('[PKT] Received message type:', msgType, 'state:', this.state);

      await this.handlePacket(packet);
    }
  }

  private async handlePacket(packet: any): Promise<void> {
    const msgType = packet.payload[0];

    switch (this.state) {
      case 'kex':
        await this.handleKEXPacket(msgType, packet.payload);
        break;

      case 'auth':
        await this.handleAuthPacket(msgType, packet.payload);
        break;

      case 'shell':
      case 'ready':
        await this.handleSessionPacket(msgType, packet.payload);
        break;
    }
  }

  private async handleKEXPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_KEXINIT:
        console.log('[KEX] Received KEXINIT from server');
        this.kexInitRemote = payload;
        break;

      case SSH_MSG_KEX_ECDH_REPLY:
        console.log('[KEX] Received ECDH_REPLY');
        await this.handleECDHReply(payload);
        break;

      case SSH_MSG_NEWKEYS:
        console.log('[KEX] Received NEWKEYS from server');

        const newKeys = new Uint8Array([SSH_MSG_NEWKEYS]);
        const packet = await SSHPacketBuilder.build(
          newKeys, 8, null, this.seqNumSend++
        );
        await this.writeSocket(packet);
        console.log('[KEX] NEWKEYS sent, seqNumSend:', this.seqNumSend);

        this.seqNumSend = 0;
        this.packetParser.resetSeqNum();
        await this.enableEncryption();
        console.log('[KEX] Encryption enabled');

        this.state = 'auth';
        console.log('[SSH] State changed to: auth');
        this.ws.send(JSON.stringify({ type: 'status', message: '加密已启用，正在请求认证服务...' }));
        await this.sendServiceRequest();
        break;
    }
  }

  private async handleECDHReply(payload: Uint8Array): Promise<void> {
    console.log('[KEX] Parsing ECDH_REPLY...');
    const { hostKey, serverRawPublicKey, signature } =
      ECDHKeyExchange.parseReply(payload);
    console.log('[KEX] ECDH_REPLY parsed, hostKey:', hostKey.length, 'serverPubKey:', serverRawPublicKey.length, 'sig:', signature.length);

    console.log('[KEX] Computing shared secret...');
    const sharedSecret = await ECDHKeyExchange.computeSharedSecret(
      this.ecdhKeyPair.privateKey,
      serverRawPublicKey
    );
    console.log('[KEX] Shared secret computed, length:', sharedSecret.length);

    console.log('[KEX] Computing exchange hash...');
    const H = await ECDHKeyExchange.computeExchangeHash(
      this.transport.getLocalVersion(),
      this.transport.getRemoteVersion(),
      this.kexInitLocal!,
      this.kexInitRemote!,
      hostKey,
      this.ecdhRawPublicKey,
      serverRawPublicKey,
      sharedSecret
    );
    console.log('[KEX] Exchange hash computed');

    if (!this.sessionID) {
      this.sessionID = H;
      console.log('[KEX] Session ID set');
    }

    console.log('[KEX] Deriving keys...');
    this.derivedKeys = await KeyDerivation.deriveKeys(sharedSecret, H, this.sessionID!);
    console.log('[KEX] Keys derived, waiting for NEWKEYS...');
  }

  private async enableEncryption(): Promise<void> {
    console.log('[KEX] Enabling encryption...');
    const keys = this.derivedKeys;

    this.encryptCipher = new SSHAESGCMCipher(
      keys.encKeyClientToServer,
      keys.ivClientToServer
    );
    await this.encryptCipher.init();

    this.decryptCipher = new SSHAESGCMCipher(
      keys.encKeyServerToClient,
      keys.ivServerToClient
    );
    await this.decryptCipher.init();
    console.log('[KEX] Encryption ciphers ready');
  }

  private async sendServiceRequest(): Promise<void> {
    console.log('[AUTH] Sending SERVICE_REQUEST for ssh-userauth...');
    const serviceName = 'ssh-userauth';
    const encoder = new TextEncoder();
    const nameBytes = encoder.encode(serviceName);
    const serviceRequest = new Uint8Array(1 + 4 + nameBytes.length);
    serviceRequest[0] = SSH_MSG_SERVICE_REQUEST;
    const view = new DataView(serviceRequest.buffer);
    view.setUint32(1, nameBytes.length, false);
    serviceRequest.set(nameBytes, 5);

    const packet = await SSHPacketBuilder.build(
      serviceRequest, 16,
      (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
      this.seqNumSend++,
      true
    );
    await this.writeSocket(packet);
    console.log('[AUTH] SERVICE_REQUEST sent');
  }

  private async authenticate(): Promise<void> {
    console.log('[AUTH] Sending password authentication...');
    const authRequest = SSHAuth.buildPasswordAuthRequest(
      this.config.username,
      this.config.password
    );
    console.log('[AUTH] Auth request built, length:', authRequest.length);

    const packet = await SSHPacketBuilder.build(
      authRequest, 16,
      (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
      this.seqNumSend++,
      true
    );
    await this.writeSocket(packet);
    console.log('[AUTH] Auth request sent');
  }

  private async handleAuthPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_SERVICE_ACCEPT:
        console.log('[AUTH] SERVICE_ACCEPT received, sending password auth...');
        this.ws.send(JSON.stringify({ type: 'status', message: '认证服务已接受，正在认证...' }));
        await this.authenticate();
        break;

      case SSH_MSG_USERAUTH_SUCCESS:
        console.log('[AUTH] Authentication successful!');
        this.ws.send(JSON.stringify({
          type: 'status',
          message: '认证成功'
        }));
        this.state = 'shell';
        console.log('[SSH] State changed to: shell');
        await this.openShell();
        break;

      case SSH_MSG_USERAUTH_FAILURE:
        console.log('[AUTH] Authentication failed');
        this.ws.send(JSON.stringify({
          type: 'error',
          message: '认证失败：用户名或密码错误'
        }));
        this.close();
        break;
    }
  }

  private async openShell(): Promise<void> {
    console.log('[SHELL] Opening session channel...');
    const openMsg = this.channel.buildOpenSession();
    await this.sendEncrypted(openMsg);
    console.log('[SHELL] Channel open request sent');
  }

  private async handleSessionPacket(msgType: number, payload: Uint8Array): Promise<void> {
    console.log('[SESSION] Received message type:', msgType);
    switch (msgType) {
      case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        console.log('[SESSION] Channel opened successfully');
        this.channel.handleOpenConfirmation(payload);
        console.log('[SESSION] Sending PTY request...');
        const ptyReq = this.channel.buildPTYRequest(120, 40);
        await this.sendEncrypted(ptyReq);
        console.log('[SESSION] PTY request sent');
        break;

      case SSH_MSG_CHANNEL_SUCCESS:
        console.log('[SESSION] Channel success, state:', this.state);
        if (this.state === 'shell') {
          console.log('[SESSION] Sending shell request...');
          const shellReq = this.channel.buildShellRequest();
          await this.sendEncrypted(shellReq);
          this.state = 'ready';
          console.log('[SSH] State changed to: ready - SHELL ACTIVE!');
        }
        break;

      case SSH_MSG_CHANNEL_DATA:
        const outputData = this.channel.handleChannelData(payload);
        this.ws.send(outputData.slice().buffer);
        break;

      case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        console.log('[SESSION] Window adjust');
        break;

      case SSH_MSG_CHANNEL_EOF:
      case SSH_MSG_CHANNEL_CLOSE:
        console.log('[SESSION] Channel closed');
        this.ws.send(JSON.stringify({
          type: 'status',
          message: '会话已结束'
        }));
        this.close();
        break;

      case SSH_MSG_DISCONNECT:
        console.log('[SESSION] Server disconnected');
        this.ws.send(JSON.stringify({
          type: 'status',
          message: '服务器断开连接'
        }));
        this.close();
        break;

      case SSH_MSG_IGNORE:
      case SSH_MSG_DEBUG:
        break;
    }
  }

  handleWebSocketMessage(data: string | ArrayBuffer): void {
    if (this.state !== 'ready') {
      console.log('[INPUT] Ignoring input, state:', this.state);
      return;
    }

    if (typeof data === 'string') {
      try {
        const msg = JSON.parse(data);
        if (msg.type === 'resize') {
          console.log('[INPUT] Terminal resize:', msg.cols, 'x', msg.rows);
          this.handleResize(msg.cols, msg.rows);
          return;
        }
      } catch {
        const encoded = new TextEncoder().encode(data);
        const channelData = this.channel.buildChannelData(encoded);
        this.sendEncrypted(channelData);
      }
    } else {
      const channelData = this.channel.buildChannelData(
        new Uint8Array(data)
      );
      this.sendEncrypted(channelData);
    }
  }

  private async handleResize(cols: number, rows: number): Promise<void> {
    const resizeMsg = this.channel.buildWindowChange(cols, rows);
    await this.sendEncrypted(resizeMsg);
  }

  private async sendEncrypted(payload: Uint8Array): Promise<void> {
    if (!this.encryptCipher) {
      throw new Error('Encryption not initialized');
    }

    const encrypted = await SSHPacketBuilder.build(
      payload, 16,
      (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
      this.seqNumSend++,
      true
    );
    await this.writeSocket(encrypted);
  }

  close(): void {
    console.log('[SSH] Closing session');
    try { this.socket.close(); } catch {}
    try { this.ws.close(); } catch {}
  }
}
