/**
 * Blob storage interface + factory. Implementations: storage/local.ts (atomic temp+rename, R21 Windows
 * retries, realpath'd root with a traversal guard) and storage/s3.ts (forcePathStyle, WHEN_REQUIRED
 * checksums, CreateBucket at init, DeleteObjects; R17).
 *
 * Blobs are ciphertext chunks addressed by (dropId, fileId, index, version). The chunk PUT writes every
 * attempt under a fresh version and only then points the DropChunk row at it (C-R2-01), so no DB lock is held
 * during storage I/O and a write never replaces a chunk that complete() verified. No version = the legacy
 * key <index>. The driver never sees plaintext.
 */
import type { Readable } from 'node:stream';
import { env, type Env } from '../config/env';
import { createLocalStorage } from './local';
import { createS3Storage } from './s3';

export interface StorageDriver {
  /** Prepare the backend at startup (local: mkdir the root; s3: create the bucket if missing). */
  init(): Promise<void>;
  /** Store (or overwrite) one ciphertext chunk under (dropId, fileId, index, version). */
  putChunk(
    dropId: string,
    fileId: string,
    index: number,
    data: Buffer,
    version?: string,
  ): Promise<void>;
  /** Stream one chunk. A missing chunk rejects with AppError NOT_FOUND (lib/errors notFound()). */
  getChunkStream(
    dropId: string,
    fileId: string,
    index: number,
    version?: string,
  ): Promise<Readable>;
  /** Delete one chunk blob (idempotent). */
  deleteChunk(dropId: string, fileId: string, index: number, version?: string): Promise<void>;
  /** Delete every blob of the drop (idempotent). */
  deleteDrop(dropId: string): Promise<void>;
  /** Used by /readyz; rejects when the backend is unreachable. */
  healthCheck(): Promise<void>;
  /** Free bytes on the volume holding the blobs (local driver only; S3 has no such limit). */
  freeBytes?(): Promise<number>;
}

export type StorageEnv = Pick<
  Env,
  | 'STORAGE_DRIVER'
  | 'STORAGE_DIR'
  | 'S3_ENDPOINT'
  | 'S3_REGION'
  | 'S3_BUCKET'
  | 'S3_ACCESS_KEY_ID'
  | 'S3_SECRET_ACCESS_KEY'
  | 'S3_FORCE_PATH_STYLE'
>;

/** Drop and file ids are b64url (22 chars); allow up to 64 base64url characters and nothing else. */
const BLOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_CHUNK_INDEX = 2 ** 32 - 1;

/** Throws unless `id` is a safe blob path segment (no separators, dots or other characters). */
export function assertDropId(id: string): void {
  if (typeof id !== 'string' || !BLOB_ID_RE.test(id)) throw new TypeError('invalid blob id');
}

/** Throws unless (dropId, fileId, index[, version]) is a valid blob address. */
export function assertBlobAddress(
  dropId: string,
  fileId: string,
  index: number,
  version?: string,
): void {
  assertDropId(dropId);
  assertDropId(fileId);
  if (!Number.isInteger(index) || index < 0 || index > MAX_CHUNK_INDEX) {
    throw new TypeError('invalid chunk index');
  }
  if (version !== undefined) assertDropId(version);
}

/** Last path segment / key part of a chunk blob: `<index>` (legacy) or `<index>.<version>`. */
export const chunkLeaf = (index: number, version?: string) =>
  version === undefined ? String(index) : `${index}.${version}`;

export function createStorage(storageEnv: StorageEnv): StorageDriver {
  if (storageEnv.STORAGE_DRIVER === 's3') return createS3Storage(storageEnv);
  return createLocalStorage(storageEnv.STORAGE_DIR);
}

let shared: StorageDriver | undefined;
/** Process-wide driver from the global env (index.ts and createApp() defaults). */
export function getDefaultStorage(): StorageDriver {
  shared ??= createStorage(env);
  return shared;
}
