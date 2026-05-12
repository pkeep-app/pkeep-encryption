/**
 * @pkeep/encryption
 *
 * Auditable encryption core for pKeep.
 * AES-256-GCM vault encryption · MetaMask key derivation · IPFS storage adapter.
 *
 * @example
 * import { deriveKeyFromSignature, encryptVault, decryptVault, uploadVault, downloadVault, SIGNING_MESSAGE } from '@pkeep/encryption';
 */

// Key derivation
export { deriveKeyFromSignature, hexToBytes, bytesToHex, SIGNING_MESSAGE } from './keys.js';

// Vault encryption / decryption
export { encryptVault, decryptVault, isEncryptedVault } from './encryption.js';

// IPFS storage adapter
export { uploadVault, downloadVault, gatewayUrl } from './storage.js';

// Types
export type {
  Vault,
  VaultEntry,
  SeedPhraseEntry,
  EncryptedVault,
  UploadResult,
  KeyDerivationParams,
} from './types.js';
