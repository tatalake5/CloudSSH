import { SSH_MSG_KEX_ECDH_INIT } from '../types';
import { concat, readUint32, encodeUint32, encodeString, toSSHMPInt, extractRawECDHPoint } from './utils';

export class ECDHKeyExchange {
  static async generateKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
  }

  static async exportPublicKeyForSSH(keyPair: CryptoKeyPair): Promise<Uint8Array> {
    const rawKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', keyPair.publicKey)
    );

    const parts: Uint8Array[] = [];

    const keyType = new TextEncoder().encode('ecdsa-sha2-nistp256');
    const keyTypeLen = new Uint8Array(4);
    new DataView(keyTypeLen.buffer).setUint32(0, keyType.length, false);

    const curveName = new TextEncoder().encode('nistp256');
    const curveNameLen = new Uint8Array(4);
    new DataView(curveNameLen.buffer).setUint32(0, curveName.length, false);

    const pointLen = new Uint8Array(4);
    new DataView(pointLen.buffer).setUint32(0, rawKey.length, false);

    const totalLen = keyTypeLen.length + keyType.length +
                     curveNameLen.length + curveName.length +
                     pointLen.length + rawKey.length;
    const totalLenBytes = new Uint8Array(4);
    new DataView(totalLenBytes.buffer).setUint32(0, totalLen, false);

    return concat(totalLenBytes, keyTypeLen, keyType,
                  curveNameLen, curveName, pointLen, rawKey);
  }

  static buildInit(clientPublicKeySSH: Uint8Array): Uint8Array {
    return concat(
      new Uint8Array([SSH_MSG_KEX_ECDH_INIT]),
      clientPublicKeySSH
    );
  }

  static parseReply(data: Uint8Array): {
    hostKey: Uint8Array;
    serverPublicKey: Uint8Array;
    signature: Uint8Array;
  } {
    let offset = 1;

    const hostKeyLen = readUint32(data, offset);
    offset += 4;
    const hostKey = data.slice(offset, offset + hostKeyLen);
    offset += hostKeyLen;

    const qSLen = readUint32(data, offset);
    offset += 4;
    const serverPublicKey = data.slice(offset, offset + qSLen);
    offset += qSLen;

    const sigLen = readUint32(data, offset);
    offset += 4;
    const signature = data.slice(offset, offset + sigLen);

    return { hostKey, serverPublicKey, signature };
  }

  static async computeSharedSecret(
    privateKey: CryptoKey,
    serverPublicKeyRaw: Uint8Array
  ): Promise<Uint8Array> {
    const rawPoint = extractRawECDHPoint(serverPublicKeyRaw);

    const serverKey = await crypto.subtle.importKey(
      'raw',
      rawPoint,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverKey },
      privateKey,
      256
    );

    return toSSHMPInt(new Uint8Array(sharedBits));
  }

  static async computeExchangeHash(
    clientVersion: string,
    serverVersion: string,
    clientKEXInit: Uint8Array,
    serverKEXInit: Uint8Array,
    hostKey: Uint8Array,
    clientPublicKeySSH: Uint8Array,
    serverPublicKeySSH: Uint8Array,
    sharedSecret: Uint8Array
  ): Promise<Uint8Array> {
    const data = concat(
      encodeString(clientVersion),
      encodeString(serverVersion),
      encodeUint32(clientKEXInit.length),
      clientKEXInit,
      encodeUint32(serverKEXInit.length),
      serverKEXInit,
      hostKey,
      clientPublicKeySSH,
      serverPublicKeySSH,
      sharedSecret
    );

    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
  }
}
