import { SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, AuthResult } from '../types';
import { encodeString, concat, readUint32 } from './utils';

export class SSHAuth {
  static buildPasswordAuthRequest(
    username: string,
    password: string
  ): Uint8Array {
    const parts: Uint8Array[] = [
      new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
      encodeString(username),
      encodeString('ssh-connection'),
      encodeString('password'),
      new Uint8Array([0x00]),
      encodeString(password),
    ];

    return concat(...parts);
  }

  static handleResponse(payload: Uint8Array): AuthResult {
    const msgType = payload[0];

    switch (msgType) {
      case SSH_MSG_USERAUTH_SUCCESS:
        return { success: true };

      case SSH_MSG_USERAUTH_FAILURE: {
        const len = readUint32(payload, 1);
        const methods = new TextDecoder().decode(
          payload.slice(5, 5 + len)
        );
        return {
          success: false,
          allowedMethods: methods.split(','),
        };
      }

      default:
        throw new Error(`Unexpected auth message type: ${msgType}`);
    }
  }
}
