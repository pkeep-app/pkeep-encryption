/**
 * @pkeep/encryption
 *
 * Auditable encryption core for pKeep — Dein dezentraler Passwort-Speicher.
 *
 * This package exposes only the cryptographic primitives:
 * - Key derivation from MetaMask signature (HKDF-SHA-256)
 * - AES-256-GCM vault encryption / decryption
 *
 * Storage, vault structure, and application logic are intentionally
 * not part of this public package.
 *
 * @example
 * import { deriveKeyFromSignature, encryptVault, decryptVault, SIGNING_MESSAGE } from '@pkeep/encryption';
 */

// Key derivation
export { deriveKeyFromSignature, hexToBytes, bytesToHex, SIGNING_MESSAGE } from './keys.js';

// Vault encryption / decryption
export { encryptVault, decryptVault, isEncryptedVault } from './encryption.js';
