import { keyPairFromSeed } from '@ton/crypto';
import { hexToBuffer } from './encoding';

export function resolveSecretKeyFromHex(privateKeyHex: string): Buffer {
  const key = hexToBuffer(privateKeyHex);

  if (key.length === 64) {
    return key;
  }

  if (key.length === 32) {
    return keyPairFromSeed(key).secretKey;
  }

  throw new Error('privateKeyHex must be 32-byte seed or 64-byte secret key');
}
