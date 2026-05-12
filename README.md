# @pkeep/encryption

[![CI](https://github.com/pkeep-app/pkeep-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/pkeep-app/pkeep-encryption/actions)
[![npm version](https://badge.fury.io/js/%40pkeep%2Fencryption.svg)](https://www.npmjs.com/package/@pkeep/encryption)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**The auditable encryption core of [pKeep](https://pkeep.app) — Dein dezentraler Passwort-Speicher.**

This repository contains the full source code for pKeep's vault encryption, key derivation, and IPFS storage adapter. It is published openly so that anyone — security researchers, auditors, or curious developers — can verify exactly how pKeep protects your data.

## What this library does

- **Derives a deterministic AES-256-GCM key** from your MetaMask signature using HKDF (NIST SP 800-56C). Your key never leaves your device.
- **Encrypts your vault** (passwords, seed phrases, notes) with AES-256-GCM (NIST SP 800-38D) — the same standard used by banks and governments.
- **Uploads and downloads** the encrypted vault to/from IPFS. The decentral Storage sees only encrypted bytes — never your plaintext.

## Security properties

| Property | Value |
|---|---|
| Encryption algorithm | AES-256-GCM |
| Key length | 256 bit |
| IV | 96 bit, random per encryption |
| Auth tag | 128 bit (GCM) |
| Key derivation | HKDF-SHA-256 from MetaMask signature |
| Integrity check | SHA-256 checksum of plaintext |
| External dependencies | **Zero** (Web Crypto API only) |

> **No server ever sees your plaintext.** The key is derived locally in your browser from your MetaMask signature. The encrypted vault is stored on IPFS — a decentralised network. Even if pKeep as a company ceased to exist, your encrypted data remains accessible by CID.

## Installation

```bash
npm install @pkeep/encryption
```

## Usage

```typescript
import {
  SIGNING_MESSAGE,
  deriveKeyFromSignature,
  encryptVault,
  decryptVault,
  uploadVault,
  downloadVault,
} from '@pkeep/encryption';

// 1. Ask MetaMask to sign the deterministic message
const signature = await window.ethereum.request({
  method: 'personal_sign',
  params: [SIGNING_MESSAGE, userAddress],
});

// 2. Derive AES-256-GCM key from the signature
const key = await deriveKeyFromSignature({
  signature,
  address: userAddress,
});

// 3. Encrypt the vault
const encrypted = await encryptVault(vault, key);

// 4. Upload to IPFS (Lighthouse)
const { cid } = await uploadVault(encrypted, lighthouseApiKey);
// Save `cid` to localStorage — it's your vault's address on IPFS

// 5. Later: download and decrypt
const downloaded = await downloadVault(cid);
const vault = await decryptVault(downloaded, key);
```

## Key derivation diagram

```
MetaMask wallet
      │
      │  signs "pKeep vault key derivation v1\n..."
      ▼
  Signature (65 bytes)
      │
      │  HKDF-SHA-256
      │  salt  = wallet address (UTF-8)
      │  info  = "pkeep-vault-aes256gcm-v1"
      ▼
  AES-256-GCM CryptoKey
      │
      │  (never extractable, never leaves browser)
      ▼
  encryptVault(vault, key) ──► EncryptedVault (JSON)
                                      │
                                      │  uploadVault()
                                      ▼
                                  IPFS / Filecoin
                               (only encrypted bytes)
```

## Running tests

```bash
npm install
npm test
```

Tests cover:
- Key derivation determinism (same inputs → same key)
- Key isolation (different signature → decryption fails)
- Encryption round-trips
- Tamper detection (modified ciphertext → error)
- IV randomness (same plaintext → different ciphertext every time)

## What is NOT in this repository

The pKeep application layer — user interface, sync logic, subscription management, and backend services — is not part of this public library. This repository contains only the cryptographic primitives that pKeep is built on.

## Auditing

We invite security researchers to review this code. If you find a vulnerability, please report it responsibly to **security@pkeep.app**.

A bug bounty program is available — see [pkeep.app/security](https://pkeep.app/security) for details.

## License

MIT — see [LICENSE](LICENSE).

---

Built with ♥ by the [pKeep team](https://pkeep.app) · [pkeep.app](https://pkeep.app)
