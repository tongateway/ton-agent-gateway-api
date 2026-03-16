export function normalizeHex(value: string): string {
  const clean = value.trim().toLowerCase().replace(/^0x/, '');
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) {
    throw new Error('Invalid hex string');
  }
  return clean;
}

export function hexToBuffer(value: string): Buffer {
  return Buffer.from(normalizeHex(value), 'hex');
}

export function bigintFromString(value: string): bigint {
  const clean = value.trim();
  if (!/^\d+$/.test(clean)) {
    throw new Error(`Invalid unsigned integer: ${value}`);
  }
  return BigInt(clean);
}
