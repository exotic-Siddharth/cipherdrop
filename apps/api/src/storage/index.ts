/**
 * Blob storage interface + factory (S4). The implementations are B2's: storage/local.ts (atomic temp+rename,
 * R21 Windows retries, realpath'd root with a traversal guard) and storage/s3.ts (forcePathStyle,
 * WHEN_REQUIRED checksums, CreateBucket at init, DeleteObjects; R17). Until then createStorage() returns a
 * stub whose operations reject with "not implemented" (init() resolves so the API can boot).
 *
 * Blobs are ciphertext chunks addressed by (dropId, fileId, index). The driver never sees plaintext.
 */
import type { Readable } from 'node:stream';
import { env, type Env } from '../config/env';

export interface StorageDriver {
  /** Prepare the backend at startup (local: mkdir the root; s3: create the bucket if missing). */
  init(): Promise<void>;
  /** Store (or overwrite: re-PUT is idempotent) one ciphertext chunk. */
  putChunk(dropId: string, fileId: string, index: number, data: Buffer): Promise<void>;
  /** Stream one chunk. A missing chunk rejects with AppError NOT_FOUND (lib/errors notFound()). */
  getChunkStream(dropId: string, fileId: string, index: number): Promise<Readable>;
  /** Delete every blob of the drop (idempotent). */
  deleteDrop(dropId: string): Promise<void>;
  /** Used by /readyz; rejects when the backend is unreachable. */
  healthCheck(): Promise<void>;
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

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- S4 stub: B2 implements the factory
export function createStorage(storageEnv: StorageEnv): StorageDriver {
  const notImplemented = (op: string) => () =>
    Promise.reject(new Error(`not implemented: storage.${op} (B2)`));
  return {
    init: async () => {},
    putChunk: notImplemented('putChunk'),
    getChunkStream: notImplemented('getChunkStream'),
    deleteDrop: notImplemented('deleteDrop'),
    healthCheck: notImplemented('healthCheck'),
  };
}

let shared: StorageDriver | undefined;
/** Process-wide driver from the global env (index.ts and createApp() defaults). */
export function getDefaultStorage(): StorageDriver {
  shared ??= createStorage(env);
  return shared;
}
