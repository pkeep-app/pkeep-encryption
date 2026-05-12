/**
 * @pkeep/crypto — Type Definitions
 * All types used across the pKeep encryption core.
 */

/** A single password entry in the vault */
export interface VaultEntry {
  id: string;
  title: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  tags?: string[];
  /** ISO 8601 timestamp */
  createdAt: string;
  /** ISO 8601 timestamp */
  updatedAt: string;
}

/** A seed phrase entry — same structure, explicit type for clarity */
export interface SeedPhraseEntry {
  id: string;
  title: string;
  /** Space-separated seed words (12 or 24) — stored encrypted */
  phrase: string;
  walletAddress?: string;
  network?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

/** The complete vault stored on IPFS */
export interface Vault {
  version: number;
  entries: VaultEntry[];
  seedPhrases: SeedPhraseEntry[];
  /** ISO 8601 */
  lastModified: string;
}

/** The encrypted vault as stored on IPFS */
export interface EncryptedVault {
  /** pKeep format version */
  v: number;
  /** Base64-encoded IV (12 bytes for AES-GCM) */
  iv: string;
  /** Base64-encoded AES-256-GCM ciphertext + auth tag */
  data: string;
  /** SHA-256 checksum of plaintext (hex) — for integrity verification */
  checksum: string;
}

/** Result from uploading to IPFS */
export interface UploadResult {
  /** IPFS Content ID */
  cid: string;
  /** Lighthouse gateway URL */
  url: string;
  /** File size in bytes */
  size: number;
}

/** Key derivation inputs */
export interface KeyDerivationParams {
  /** Ethereum signature from MetaMask signing the deterministic message */
  signature: string;
  /** Ethereum wallet address (used as salt) */
  address: string;
}
