/**
 * @pkeep/crypto — Key Derivation
 *
 * Derives a deterministic AES-256-GCM key from a MetaMask signature.
 *
 * Flow:
 *   1. User signs a fixed message with MetaMask → unique 65-byte signature
 *   2. Signature bytes → HKDF → AES-256-GCM CryptoKey
 *   3. Key never leaves the browser — no server, no transmission
 *
 * Security properties:
 *   - Key is derived purely from the user's private key (via signature)
 *   - Same wallet + same message → same key (deterministic)
 *   - Different wallet → completely different key
 *   - Uses HKDF (NIST SP 800-56C) with SHA-256
 */

import type { KeyDerivationParams } from './types.js';

/**
 * The message MetaMask signs to derive the vault key.
 * MUST remain constant — changing it invalidates all existing vaults.
 * Contains a version tag so future key rotation is possible.
 */
export const SIGNING_MESSAGE =
  'pKeep vault key derivation v1\n\n' +
  'Sign this message to unlock your encrypted vault.\n' +
  'This signature never leaves your device.\n\n' +
  'WARNING: Only sign on pkeep.app';

/**
 * Derives a deterministic AES-256-GCM CryptoKey from a MetaMask signature.
 *
 * @param params - signature (hex string from eth_sign) + wallet address
 * @returns AES-256-GCM CryptoKey usable for encrypt/decrypt
 */
export async function deriveKeyFromSignature(
  params: KeyDerivationParams
): Promise<CryptoKey> {
  const { signature, address } = params;

  // 1. Decode the hex signature → raw bytes (65 bytes: r+s+v)
  const sigBytes = hexToBytes(signature);

  // 2. Import raw signature bytes as HKDF key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    sigBytes.buffer as ArrayBuffer,
    { name: 'HKDF' },
    false,             // not extractable
    ['deriveKey']
  );

  // 3. Derive AES-256-GCM key via HKDF
  //    - Salt: normalized wallet address (lowercase, UTF-8)
  //    - Info: application-specific context string
  const salt = new TextEncoder().encode(address.toLowerCase());
  const info = new TextEncoder().encode('pkeep-vault-aes256gcm-v1');

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,            // not extractable — key can never be read out
    ['encrypt', 'decrypt']
  );

  return aesKey;
}

/**
 * Converts a hex string (with or without 0x prefix) to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (isNaN(byte)) throw new Error(`Invalid hex character at position ${i * 2}`);
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Converts Uint8Array to hex string (without 0x prefix).
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
