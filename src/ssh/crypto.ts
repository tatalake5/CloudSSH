export class SSHAESGCMCipher {
  private key: CryptoKey | null = null;
  private baseIV: Uint8Array;
  private seqNum: number = 0;
  private rawKey: Uint8Array;

  constructor(rawKey: Uint8Array, iv: Uint8Array) {
    this.baseIV = iv;
    this.rawKey = rawKey;
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private buildNonce(seqNum: number): Uint8Array {
    const nonce = new Uint8Array(12);
    nonce.set(this.baseIV.slice(0, 4), 0);
    const view = new DataView(nonce.buffer);
    view.setUint32(4, 0, false);
    view.setUint32(8, seqNum, false);
    return nonce;
  }

  async encrypt(plaintext: Uint8Array, seqNum?: number): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const seq = seqNum ?? this.seqNum++;
    const nonce = this.buildNonce(seq);

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        this.key,
        plaintext
      )
    );

    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, seqNum?: number): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const seq = seqNum ?? this.seqNum++;
    const nonce = this.buildNonce(seq);

    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: nonce, tagLength: 128 },
          this.key,
          ciphertext
        )
      );
      return decrypted;
    } catch (e) {
      return null;
    }
  }
}

export const REKEY_THRESHOLD = 1 << 30;

export function shouldRekey(seqNum: number): boolean {
  return seqNum >= REKEY_THRESHOLD;
}
