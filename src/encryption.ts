/**
 * @pkeep/encryption — Vault Encryption & Decryption
 *
 * Uses AES-256-GCM (NIST SP 800-38D) via the Web Crypto API.
 *
 * Security properties:
 *   - 256-bit key (derived from MetaMask signature via HKDF)
 *   - 96-bit random IV per encryption (NIST recommended for GCM)
 *   - 128-bit GCM authentication tag (verifies integrity + authenticity)
 *   - SHA-256 checksum of plaintext for additional integrity check
 *   - Zero external dependencies — uses only the browser's built-in
 *     Web Crypto API (SubtleCrypto), available in all modern browsers
 *     and Node.js >= 18
 */

// ─── Minimal types (storage and vault structure are private) ─────────────

/** The plaintext vault — structure is intentionally kept private */
export interface Vault {
  version: number;
  entries: unknown[];
  seedPhrases: unknown[];
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
  /** SHA-256 checksum of plaintext (hex) */
  checksum: string;
}

const VAULT_VERSION = 1;
const IV_LENGTH_BYTES = 12; // 96 bits — NIST recommended for AES-GCM

// ─── Encode / Decode helpers ─────────────────────────────────────────────

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─── Public API ──────────────────────────────────────────────────────────

/**
 * Encrypts the entire vault with AES-256-GCM.
 *
 * @param vault   - plaintext Vault object
 * @param key     - AES-256-GCM CryptoKey (from deriveKeyFromSignature)
 * @returns       - EncryptedVault ready to be serialised and stored on IPFS
 *
 * @example
 * const encrypted = await encryptVault(vault, key);
 * const json = JSON.stringify(encrypted); // store this on IPFS
 */
export async function encryptVault(
  vault: Vault,
  key: CryptoKey
): Promise<EncryptedVault> {
  const plaintext = JSON.stringify(vault);
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // Fresh random IV for every encryption — never reuse an IV with the same key
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintextBytes.buffer as ArrayBuffer
  );

  const checksum = await sha256Hex(plaintext);

  return {
    v: VAULT_VERSION,
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(ciphertext)),
    checksum,
  };
}

/**
 * Decrypts an EncryptedVault back to a plaintext Vault.
 *
 * Throws if:
 *  - The GCM authentication tag fails (wrong key or tampered data)
 *  - The plaintext checksum does not match (corruption)
 *  - The vault version is unsupported
 *
 * @param encrypted - EncryptedVault from IPFS
 * @param key       - AES-256-GCM CryptoKey (from deriveKeyFromSignature)
 * @returns         - plaintext Vault object
 *
 * @example
 * const vault = await decryptVault(encrypted, key);
 */
export async function decryptVault(
  encrypted: EncryptedVault,
  key: CryptoKey
): Promise<Vault> {
  if (encrypted.v !== VAULT_VERSION) {
    throw new Error(
      `Unsupported vault version: ${encrypted.v}. ` +
      `Please update @pkeep/encryption.`
    );
  }

  const iv = fromBase64(encrypted.iv);
  const ciphertext = fromBase64(encrypted.data);

  let plaintextBytes: ArrayBuffer;
  try {
    plaintextBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      key,
      ciphertext.buffer as ArrayBuffer
    );
  } catch {
    // AES-GCM throws a generic DOMException on auth-tag failure.
    // We wrap it with a clearer message.
    throw new Error(
      'Decryption failed: wrong key or data has been tampered with.'
    );
  }

  const plaintext = new TextDecoder().decode(plaintextBytes);

  // Integrity double-check: verify SHA-256 checksum
  const actualChecksum = await sha256Hex(plaintext);
  if (actualChecksum !== encrypted.checksum) {
    throw new Error(
      'Vault integrity check failed: checksum mismatch. ' +
      'The data may be corrupted.'
    );
  }

  return JSON.parse(plaintext) as Vault;
}

/**
 * Returns true if the given object looks like a valid EncryptedVault.
 * Useful for type-narrowing before calling decryptVault.
 */
export function isEncryptedVault(obj: unknown): obj is EncryptedVault {
  if (typeof obj !== 'object' || obj === null) return false;
  const e = obj as Record<string, unknown>;
  return (
    typeof e['v'] === 'number' &&
    typeof e['iv'] === 'string' &&
    typeof e['data'] === 'string' &&
    typeof e['checksum'] === 'string'
  );
}
