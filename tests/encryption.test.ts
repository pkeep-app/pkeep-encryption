/**
 * @pkeep/encryption — Tests
 *
 * Run with: npm test
 */

import { describe, it, expect } from 'vitest';
import {
  deriveKeyFromSignature,
  encryptVault,
  decryptVault,
  isEncryptedVault,
  hexToBytes,
  bytesToHex,
} from '../src/index.js';
import type { Vault } from '../src/encryption.js';

// ─── Fixtures ────────────────────────────────────────────────────────────

const MOCK_ADDRESS = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045';

// A real MetaMask signature is 65 bytes / 130 hex chars
const MOCK_SIGNATURE =
  '0x' + 'ab'.repeat(32) + 'cd'.repeat(32) + '1b';

const MOCK_VAULT: Vault = {
  version: 1,
  lastModified: '2026-05-12T10:00:00Z',
  entries: [
    {
      id: 'entry-1',
      title: 'GitHub',
      username: 'alice@example.com',
      password: 'super-secret-password-123!',
      url: 'https://github.com',
      tags: ['dev'],
      createdAt: '2026-05-12T09:00:00Z',
      updatedAt: '2026-05-12T09:00:00Z',
    },
  ],
  seedPhrases: [
    {
      id: 'seed-1',
      title: 'MetaMask Main Wallet',
      phrase: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      walletAddress: MOCK_ADDRESS,
      network: 'Ethereum',
      createdAt: '2026-05-12T09:00:00Z',
      updatedAt: '2026-05-12T09:00:00Z',
    },
  ],
};

// ─── Key Derivation Tests ────────────────────────────────────────────────

describe('deriveKeyFromSignature', () => {
  it('returns a CryptoKey with correct algorithm', async () => {
    const key = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
    expect(key.extractable).toBe(false);
  });

  it('produces the same key for the same signature + address', async () => {
    // Two keys from the same inputs should produce identical ciphertext
    // (we verify this by round-trip encrypting with key1, decrypting with key2)
    const key1 = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });
    const key2 = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    const encrypted = await encryptVault(MOCK_VAULT, key1);
    const decrypted = await decryptVault(encrypted, key2);
    expect(decrypted.entries[0]?.password).toBe('super-secret-password-123!');
  });

  it('produces a different key for a different signature', async () => {
    const DIFFERENT_SIGNATURE = '0x' + 'ff'.repeat(65);
    const key1 = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });
    const key2 = await deriveKeyFromSignature({
      signature: DIFFERENT_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    const encrypted = await encryptVault(MOCK_VAULT, key1);
    await expect(decryptVault(encrypted, key2)).rejects.toThrow(
      'Decryption failed'
    );
  });

  it('throws on invalid hex signature', async () => {
    await expect(
      deriveKeyFromSignature({ signature: 'not-hex', address: MOCK_ADDRESS })
    ).rejects.toThrow('Invalid hex');
  });
});

// ─── hex helpers ─────────────────────────────────────────────────────────

describe('hexToBytes / bytesToHex', () => {
  it('round-trips correctly', () => {
    const hex = 'deadbeef01234567';
    const bytes = hexToBytes(hex);
    expect(bytesToHex(bytes)).toBe(hex);
  });

  it('handles 0x prefix', () => {
    const bytes = hexToBytes('0xdeadbeef');
    expect(bytesToHex(bytes)).toBe('deadbeef');
  });

  it('throws on odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow('odd length');
  });
});

// ─── Encryption / Decryption Tests ───────────────────────────────────────

describe('encryptVault / decryptVault', () => {
  it('round-trips a vault correctly', async () => {
    const key = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    const encrypted = await encryptVault(MOCK_VAULT, key);
    const decrypted = await decryptVault(encrypted, key);

    expect(decrypted.version).toBe(1);
    expect(decrypted.entries).toHaveLength(1);
    expect(decrypted.entries[0]?.title).toBe('GitHub');
    expect(decrypted.entries[0]?.password).toBe('super-secret-password-123!');
    expect(decrypted.seedPhrases[0]?.phrase).toContain('abandon');
  });

  it('produces different ciphertext on every call (random IV)', async () => {
    const key = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    const enc1 = await encryptVault(MOCK_VAULT, key);
    const enc2 = await encryptVault(MOCK_VAULT, key);

    // Same plaintext, different IV → different ciphertext
    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.data).not.toBe(enc2.data);
    // But same checksum (same plaintext)
    expect(enc1.checksum).toBe(enc2.checksum);
  });

  it('throws on wrong key (auth tag failure)', async () => {
    const key1 = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });
    const key2 = await deriveKeyFromSignature({
      signature: '0x' + 'aa'.repeat(65),
      address: MOCK_ADDRESS,
    });

    const encrypted = await encryptVault(MOCK_VAULT, key1);
    await expect(decryptVault(encrypted, key2)).rejects.toThrow(
      'Decryption failed: wrong key or data has been tampered with.'
    );
  });

  it('throws on tampered ciphertext', async () => {
    const key = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    const encrypted = await encryptVault(MOCK_VAULT, key);
    // Flip one character in the ciphertext
    const tampered = {
      ...encrypted,
      data: encrypted.data.slice(0, -2) + 'AA',
    };

    await expect(decryptVault(tampered, key)).rejects.toThrow('Decryption failed');
  });

  it('throws on unsupported vault version', async () => {
    const key = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });

    const encrypted = await encryptVault(MOCK_VAULT, key);
    const future = { ...encrypted, v: 99 };
    await expect(decryptVault(future, key)).rejects.toThrow('Unsupported vault version');
  });
});

// ─── isEncryptedVault ─────────────────────────────────────────────────────

describe('isEncryptedVault', () => {
  it('returns true for a valid shape', async () => {
    const key = await deriveKeyFromSignature({
      signature: MOCK_SIGNATURE,
      address: MOCK_ADDRESS,
    });
    const encrypted = await encryptVault(MOCK_VAULT, key);
    expect(isEncryptedVault(encrypted)).toBe(true);
  });

  it('returns false for invalid shapes', () => {
    expect(isEncryptedVault(null)).toBe(false);
    expect(isEncryptedVault({ v: 1 })).toBe(false);
    expect(isEncryptedVault({ v: 1, iv: 'x', data: 'x' })).toBe(false);
    expect(isEncryptedVault('string')).toBe(false);
  });
});
