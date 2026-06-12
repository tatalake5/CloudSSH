import {
  SSH_MSG_CHANNEL_OPEN,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_REQUEST,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_FAILURE
} from '../types';
import { encodeString, encodeUint32, readUint32, concat } from './utils';

export class SSHChannel {
  private localChannelID: number = 0;
  private remoteChannelID: number = 0;
  private localWindowSize: number = 2097152;
  private remoteWindowSize: number = 0;
  private maxPacketSize: number = 32768;

  buildOpenSession(): Uint8Array {
    this.localChannelID = 0;

    return concat(
      new Uint8Array([SSH_MSG_CHANNEL_OPEN]),
      encodeString('session'),
      encodeUint32(this.localChannelID),
      encodeUint32(this.localWindowSize),
      encodeUint32(this.maxPacketSize)
    );
  }

  handleOpenConfirmation(payload: Uint8Array): void {
    let offset = 1;
    offset += 4;
    this.remoteChannelID = readUint32(payload, offset);
    offset += 4;
    this.remoteWindowSize = readUint32(payload, offset);
    offset += 4;
    const serverMaxPacket = readUint32(payload, offset);
    this.maxPacketSize = Math.min(this.maxPacketSize, serverMaxPacket);
  }

  buildPTYRequest(cols: number, rows: number): Uint8Array {
    const modes = new Uint8Array([0]);

    return concat(
      new Uint8Array([SSH_MSG_CHANNEL_REQUEST]),
      encodeUint32(this.remoteChannelID),
      encodeString('pty-req'),
      new Uint8Array([0x01]),
      encodeString('xterm-256color'),
      encodeUint32(cols),
      encodeUint32(rows),
      encodeUint32(0),
      encodeUint32(0),
      encodeString(modes)
    );
  }

  buildShellRequest(): Uint8Array {
    return concat(
      new Uint8Array([SSH_MSG_CHANNEL_REQUEST]),
      encodeUint32(this.remoteChannelID),
      encodeString('shell'),
      new Uint8Array([0x01])
    );
  }

  buildChannelData(data: Uint8Array): Uint8Array {
    return concat(
      new Uint8Array([SSH_MSG_CHANNEL_DATA]),
      encodeUint32(this.remoteChannelID),
      encodeUint32(data.length),
      data
    );
  }

  handleChannelData(payload: Uint8Array): Uint8Array {
    let offset = 1;
    offset += 4;
    const dataLen = readUint32(payload, offset);
    offset += 4;
    return payload.slice(offset, offset + dataLen);
  }

  buildWindowChange(cols: number, rows: number): Uint8Array {
    return concat(
      new Uint8Array([SSH_MSG_CHANNEL_REQUEST]),
      encodeUint32(this.remoteChannelID),
      encodeString('window-change'),
      new Uint8Array([0x00]),
      encodeUint32(cols),
      encodeUint32(rows),
      encodeUint32(0),
      encodeUint32(0)
    );
  }
}
