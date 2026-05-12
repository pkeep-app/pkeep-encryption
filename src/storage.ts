/**
 * @pkeep/encryption — IPFS Storage Adapter
 *
 * Thin adapter for uploading and downloading encrypted vault data
 * via Lighthouse (IPFS + Filecoin permanent storage).
 *
 * Note: This adapter is intentionally storage-agnostic.
 * The EncryptedVault JSON is already fully encrypted before it
 * reaches this layer — the storage backend never sees plaintext.
 *
 * To swap backends (e.g. web3.storage, nft.storage), only this
 * file needs to change.
 */

import type { EncryptedVault, UploadResult } from './types.js';

const LIGHTHOUSE_UPLOAD_URL = 'https://node.lighthouse.storage/api/v0/add';
const IPFS_GATEWAY = 'https://gateway.lighthouse.storage/ipfs';

/**
 * Uploads an EncryptedVault to IPFS via Lighthouse.
 *
 * The data is already encrypted before calling this function —
 * Lighthouse never receives the plaintext vault.
 *
 * @param encrypted   - encrypted vault object
 * @param apiKey      - Lighthouse API key (user's own key or pKeep's shared key)
 * @returns           - UploadResult with CID and gateway URL
 *
 * @example
 * const result = await uploadVault(encrypted, process.env.LIGHTHOUSE_API_KEY);
 * console.log(result.cid); // "QmXyz..."
 */
export async function uploadVault(
  encrypted: EncryptedVault,
  apiKey: string
): Promise<UploadResult> {
  if (!apiKey) throw new Error('Lighthouse API key is required.');

  const json = JSON.stringify(encrypted);
  const blob = new Blob([json], { type: 'application/json' });

  const formData = new FormData();
  formData.append('file', blob, 'vault.json');

  const response = await fetch(LIGHTHOUSE_UPLOAD_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
    },
    body: formData,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new Error(`Lighthouse upload failed (${response.status}): ${text}`);
  }

  const result = (await response.json()) as {
    Hash: string;
    Size: string;
    Name: string;
  };

  const cid = result.Hash;

  return {
    cid,
    url: `${IPFS_GATEWAY}/${cid}`,
    size: parseInt(result.Size, 10),
  };
}

/**
 * Downloads and parses an EncryptedVault from IPFS by CID.
 *
 * No API key needed — IPFS content is publicly readable by CID.
 * The data is still encrypted; only the correct key can decrypt it.
 *
 * @param cid - IPFS Content ID (e.g. "QmXyz...")
 * @returns   - EncryptedVault object (still encrypted)
 *
 * @example
 * const encrypted = await downloadVault('QmXyz...');
 */
export async function downloadVault(cid: string): Promise<EncryptedVault> {
  if (!cid) throw new Error('CID is required.');

  const url = `${IPFS_GATEWAY}/${cid}`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(
      `Failed to fetch vault from IPFS (${response.status}): ${response.statusText}\n` +
      `CID: ${cid}`
    );
  }

  const data: unknown = await response.json();

  if (!isEncryptedVaultShape(data)) {
    throw new Error(
      'Downloaded data does not look like a pKeep vault. ' +
      'The CID may be incorrect or the data is corrupted.'
    );
  }

  return data;
}

/**
 * Returns the public IPFS gateway URL for a given CID.
 * Useful for sharing or bookmarking a vault location.
 */
export function gatewayUrl(cid: string): string {
  return `${IPFS_GATEWAY}/${cid}`;
}

// ─── Internal type guard ──────────────────────────────────────────────────

function isEncryptedVaultShape(obj: unknown): obj is EncryptedVault {
  if (typeof obj !== 'object' || obj === null) return false;
  const e = obj as Record<string, unknown>;
  return (
    typeof e['v'] === 'number' &&
    typeof e['iv'] === 'string' &&
    typeof e['data'] === 'string' &&
    typeof e['checksum'] === 'string'
  );
}
