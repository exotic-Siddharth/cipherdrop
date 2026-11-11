/**
 * Verified download pipeline (spec 11.3, 7.2; R10, R12, R14). Main thread, but DOM-free so node tests can
 * drive it (R20).
 *
 * A DownloadSession holds one grant (from /open, or the admin review grant) and reuses it for every file
 * while the server accepts it; it never re-opens on its own, because re-opening consumes a download (R12).
 * For each file it fetches the chunks in order, feeds them to createChunkDecryptor (which enforces positions
 * and the final-chunk flag) and writes plaintext to a FileSink; the sink only produces a file on close(), so
 * any failure aborts the file and nothing tampered is ever saved.
 *
 * Failure taxonomy (R14):
 * - network errors, 429 and 5xx: retried with backoff (3 attempts, Retry-After honoured), then the ApiError
 *   is rethrown (isRetryable === true) for a retryable error state;
 * - 401 on a chunk GET: the grant expired (R12) -> GrantExpiredError;
 * - an authentication failure: IntegrityError from @cipherdrop/crypto, the ONLY error that means "modified".
 */
import {
  createChunkDecryptor,
  deriveFileKey,
  IntegrityError,
  MAX_CHUNK_CIPHERTEXT_BYTES,
  type ManifestFile,
} from '@cipherdrop/crypto';
import { apiUrl, errorFromResponse, isApiError, networkError } from '../lib/http';
import type { FileSink } from './sinks';
import { chunkPath, retryWithBackoff, type Sleep } from './uploader';

/** 3 attempts per chunk GET (R14). */
export const DOWNLOAD_RETRY_DELAYS_MS: readonly number[] = [500, 2000];

export interface DownloadGrant {
  downloadToken: string;
  expiresAt: string;
  /** Present for /open grants; absent for admin review grants. */
  downloadsRemaining?: number;
}

/** The download window closed (expired grant). Re-opening needs the user's confirmation (R12). */
export class GrantExpiredError extends Error {
  readonly code = 'GRANT_EXPIRED' as const;
  constructor(message = 'The download window expired.') {
    super(message);
    this.name = 'GrantExpiredError';
  }
}

export function isGrantExpiredError(err: unknown): err is GrantExpiredError {
  return (err as { code?: unknown } | null)?.code === 'GRANT_EXPIRED';
}

export function isIntegrityError(err: unknown): boolean {
  return err instanceof IntegrityError || (err as { code?: unknown } | null)?.code === 'INTEGRITY';
}

export interface DownloadSessionOptions {
  dropId: string;
  dk: Uint8Array;
  /** Obtain a grant: POST /drops/:id/open (consumes a download) or the admin review grant. */
  open: () => Promise<DownloadGrant>;
  /** Start with an existing grant (e.g. the admin review grant fetched together with the manifest). */
  grant?: DownloadGrant | null;
  baseUrl?: string;
  delays?: readonly number[];
  sleep?: Sleep;
}

export interface DownloadFileOptions {
  signal?: AbortSignal;
  /** Plaintext bytes written so far, after each chunk. */
  onProgress?: (writtenBytes: number, totalBytes: number) => void;
  onRetry?: (err: unknown, retry: number, delayMs: number) => void;
}

export class DownloadSession {
  private grant: DownloadGrant | null;
  private expired = false;
  private opening: Promise<DownloadGrant> | null = null;
  private readonly keys = new Map<string, Promise<CryptoKey>>();

  constructor(private readonly opts: DownloadSessionOptions) {
    this.grant = opts.grant ?? null;
  }

  get currentGrant(): DownloadGrant | null {
    return this.grant;
  }

  get hasExpired(): boolean {
    return this.expired;
  }

  /** Obtain a grant (single-flight). After an expiry this is the explicit, user-confirmed re-open. */
  async open(): Promise<DownloadGrant> {
    this.opening ??= this.opts.open().then(
      (g) => {
        this.grant = g;
        this.expired = false;
        this.opening = null;
        return g;
      },
      (err: unknown) => {
        this.opening = null;
        throw err;
      },
    );
    return this.opening;
  }

  private async ensureGrant(): Promise<DownloadGrant> {
    if (this.grant) return this.grant;
    if (this.expired) throw new GrantExpiredError();
    return this.open();
  }

  private fileKey(fileId: string): Promise<CryptoKey> {
    let k = this.keys.get(fileId);
    if (!k) {
      k = deriveFileKey(this.opts.dk, fileId);
      this.keys.set(fileId, k);
    }
    return k;
  }

  private async fetchChunk(
    token: string,
    fileId: string,
    index: number,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    let res: Response;
    try {
      res = await fetch(
        apiUrl(chunkPath(this.opts.dropId, fileId, index), { baseUrl: this.opts.baseUrl }),
        {
          method: 'GET',
          headers: { authorization: `Bearer ${token}`, accept: 'application/octet-stream' },
          credentials: 'same-origin',
          cache: 'no-store',
          signal,
        },
      );
    } catch (err) {
      throw networkError(err);
    }
    if (res.status === 401) {
      void res.body?.cancel().catch(() => undefined);
      throw new GrantExpiredError();
    }
    if (!res.ok) throw await errorFromResponse(res);
    try {
      return new Uint8Array(await res.arrayBuffer());
    } catch (err) {
      // The connection dropped mid-body: retryable like any network failure.
      throw networkError(err);
    }
  }

  /**
   * Download, verify and decrypt one file into `sink`. Resolves with sink.close() (the Blob for Blob sinks).
   * On any failure the sink is aborted first, then the error is rethrown.
   */
  async downloadFile(
    file: ManifestFile,
    sink: FileSink,
    options: DownloadFileOptions = {},
  ): Promise<Blob | null> {
    const { signal } = options;
    try {
      const key = await this.fileKey(file.id);
      const decryptor = createChunkDecryptor(key, file.chunkCount);
      let written = 0;
      for (let index = 0; index < file.chunkCount; index++) {
        if (signal?.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
        const ct = await retryWithBackoff(
          async () => {
            const grant = await this.ensureGrant();
            try {
              return await this.fetchChunk(grant.downloadToken, file.id, index, signal);
            } catch (err) {
              if (isGrantExpiredError(err)) {
                this.grant = null;
                this.expired = true;
              }
              throw err;
            }
          },
          {
            delays: this.opts.delays ?? DOWNLOAD_RETRY_DELAYS_MS,
            signal,
            sleep: this.opts.sleep,
            onRetry: options.onRetry,
          },
        );
        if (ct.length > MAX_CHUNK_CIPHERTEXT_BYTES) {
          throw new IntegrityError(`Chunk ${index} is larger than a chunk can be`);
        }
        const pt = await decryptor.decryptNext(ct);
        written += pt.length;
        if (written > file.size)
          throw new IntegrityError('The file is larger than its manifest says');
        await sink.write(pt);
        options.onProgress?.(written, file.size);
      }
      if (!decryptor.done() || written !== file.size) {
        throw new IntegrityError('The file is incomplete');
      }
      return await sink.close();
    } catch (err) {
      await sink.abort();
      throw err;
    }
  }
}

/** Is this failure worth a "Try again" button (network/429/5xx after the retries)? */
export function isRetryableDownloadError(err: unknown): boolean {
  return isApiError(err) && err.isRetryable;
}
