export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function readUint32(data: Uint8Array, offset: number): number {
  return (data[offset] << 24) | (data[offset + 1] << 16) |
         (data[offset + 2] << 8) | data[offset + 3];
}

export function encodeUint32(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value, false);
  return buf;
}

export function encodeString(input: string | Uint8Array): Uint8Array {
  const encoded = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input;
  const len = encodeUint32(encoded.length);
  return concat(len, encoded);
}

export function toSSHMPInt(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  let significant = bytes.slice(start);

  if (significant[0] & 0x80) {
    significant = concat(new Uint8Array([0]), significant);
  }

  return encodeString(significant);
}

export function extractRawECDHPoint(blob: Uint8Array): Uint8Array {
  let offset = 0;

  const keyTypeLen = readUint32(blob, offset);
  offset += 4 + keyTypeLen;

  const curveLen = readUint32(blob, offset);
  offset += 4 + curveLen;

  const pointLen = readUint32(blob, offset);
  offset += 4;

  return blob.slice(offset, offset + pointLen);
}

export function encodePrefixedString(str: string): Uint8Array {
  const encoded = new TextEncoder().encode(str);
  return concat(encodeUint32(encoded.length), encoded);
}
