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
    const nonce = new Uint8Array(this.baseIV);
    const view = new DataView(nonce.buffer);
    const lo = view.getUint32(8, false);
    view.setUint32(8, lo ^ seqNum, false);
    return nonce;
  }

  async encrypt(plaintext: Uint8Array, seqNum?: number, aad?: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const seq = seqNum ?? this.seqNum++;
    const nonce = this.buildNonce(seq);

    const alg: AesGcmParams = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(alg, this.key, plaintext)
    );

    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, seqNum?: number, aad?: Uint8Array): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const seq = seqNum ?? this.seqNum++;
    const nonce = this.buildNonce(seq);

    const alg: AesGcmParams = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(alg, this.key, ciphertext)
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
