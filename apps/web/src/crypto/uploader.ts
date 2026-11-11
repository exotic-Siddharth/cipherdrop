/**
 * Upload pipeline (spec 11.3, 7.2, 7.3; R5, R7, R10, R11, R14). Worker-safe: no DOM, no stores, no lib/api.
 *
 * - prepareDrop() runs on the main thread: drop key, file ids, chunk counts, the encrypted manifest, the
 *   optional password protection (injected, so the Argon2id work can run in kdf.worker) and the owner wrap
 *   (computed BEFORE the upload starts, so a vault lock mid-upload changes nothing, R7). The result's
 *   `request` is the exact POST /drops body: ids, sizes, counts, hashes and wrapped keys only.
 * - uploadDropFiles() runs inside upload.worker: slice -> encryptChunk -> SHA-256 -> PUT, up to 3 chunks in
 *   flight, retries with backoff 0.5 s / 2 s / 8 s that honours Retry-After (R10), cancel via AbortSignal.
 * - verifyResume() implements the R11 resume check: re-encrypt the last received chunk of every file and
 *   compare its hash with upload-status; any mismatch means "start a fresh drop" (no nonce reuse with a
 *   different plaintext under the same key).
 * - Errors cross the worker boundary as {code, message} (serializeUploadError / deserializeUploadError).
 */
import {
  AAD,
  chunkCount as chunkCountFor,
  CHUNK_SIZE,
  ciphertextSize,
  deriveFileKey,
  encryptChunk,
  encryptManifest,
  generateDropKey,
  generateFileId,
  MAX_FILE_NAME_CHARS,
  MAX_FILE_TYPE_CHARS,
  sha256,
  toHex,
  wrapKey,
  type Manifest,
  type PasswordProtection,
} from '@cipherdrop/crypto';
import {
  CHUNK_SHA256_HEADER,
  type CreateDropRequest,
  type DownloadOption,
  type UploadStatus,
} from '@cipherdrop/shared';
import { ApiError, isApiError, putBinary, type ApiErrorCode } from '../lib/http';

/* ---------------------------------------------------------------------------------------------- */
/* Retry                                                                                           */
/* ---------------------------------------------------------------------------------------------- */

/** Chunk PUT retry schedule: 3 retries after the first attempt (spec 11.3). */
export const UPLOAD_RETRY_DELAYS_MS: readonly number[] = [500, 2000, 8000];
/** Chunks in flight per upload. */
export const UPLOAD_CONCURRENCY = 3;
/** Never wait longer than this for a single Retry-After. */
export const MAX_RETRY_AFTER_MS = 120_000;
/** Bytes of each latest ciphertext chunk shown by HexStream. */
export const CIPHER_PREVIEW_BYTES = 48;

export type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;

function abortError(): DOMException {
  return new DOMException('The operation was aborted.', 'AbortError');
}

/** setTimeout as a promise that rejects with an AbortError when `signal` aborts. */
export const abortableSleep: Sleep = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const id = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(id);
      reject(abortError());
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });

/** The wait before the next attempt: the backoff step, or the server's Retry-After when longer (R10). */
export function retryDelayFor(err: unknown, backoffMs: number): number {
  const retryAfter = isApiError(err) ? err.retryAfter : undefined;
  if (retryAfter === undefined) return backoffMs;
  return Math.min(MAX_RETRY_AFTER_MS, Math.max(backoffMs, retryAfter * 1000));
}

export function isRetryableError(err: unknown): boolean {
  return isApiError(err) && err.isRetryable;
}

export interface RetryOptions {
  /** One entry per retry; the number of attempts is delays.length + 1. */
  delays: readonly number[];
  signal?: AbortSignal;
  sleep?: Sleep;
  isRetryable?: (err: unknown) => boolean;
  onRetry?: (err: unknown, retry: number, delayMs: number) => void;
}

/** Run `fn`, retrying retryable failures (network, 429, 5xx: R14) on the given schedule. */
export async function retryWithBackoff<T>(
  fn: (attempt: number) => Promise<T>,
  opts: RetryOptions,
): Promise<T> {
  const sleep = opts.sleep ?? abortableSleep;
  const retryable = opts.isRetryable ?? isRetryableError;
  for (let attempt = 0; ; attempt++) {
    if (opts.signal?.aborted) throw abortError();
    try {
      return await fn(attempt);
    } catch (err) {
      const base = opts.delays[attempt];
      if (base === undefined || !retryable(err) || opts.signal?.aborted) throw err;
      const delay = retryDelayFor(err, base);
      opts.onRetry?.(err, attempt + 1, delay);
      await sleep(delay, opts.signal);
    }
  }
}

/* ---------------------------------------------------------------------------------------------- */
/* Prepare (main thread)                                                                           */
/* ---------------------------------------------------------------------------------------------- */

/** What the pipeline needs from a File (a File satisfies it). */
export interface FileLike extends Blob {
  readonly name: string;
  readonly lastModified: number;
}

/** One file as the worker uploads it. */
export interface UploadFileJob {
  id: string;
  file: Blob;
  chunkCount: number;
  /** Chunk indexes the server already has (resume). */
  skip?: readonly number[];
}

export interface PreparedFile extends UploadFileJob {
  ciphertextBytes: number;
}

export interface PrepareDropOptions {
  files: readonly FileLike[];
  /** Blank notes are sent as null. */
  note: string | null;
  expiresInHours: number;
  maxDownloads: DownloadOption;
  /** Set for password drops (the link then has no fragment). */
  password?: string | null;
  /** Argon2id protection of DK; the page passes kdfClient.createPasswordProtection (runs in a worker). */
  protect?: (dk: Uint8Array, password: string) => Promise<PasswordProtection>;
  /** Signed in with an unlocked vault: ownerWrappedKey = wrap(AK, DK, "cipherdrop/v1/wrap/owner"). */
  accountKey?: CryptoKey | null;
  now?: number;
}

export interface PreparedDrop {
  dk: Uint8Array<ArrayBuffer>;
  manifest: Manifest;
  files: PreparedFile[];
  /** The POST /drops body. */
  request: CreateDropRequest;
}

/** Truncate to at most `max` UTF-16 units without splitting a surrogate pair. */
function clampUnits(s: string, max: number): string {
  if (s.length <= max) return s;
  let out = '';
  for (const c of s) {
    if (out.length + c.length > max) break;
    out += c;
  }
  return out;
}

export async function prepareDrop(opts: PrepareDropOptions): Promise<PreparedDrop> {
  if (opts.files.length === 0) throw new RangeError('A drop needs at least one file');
  const dk = generateDropKey();
  const files: PreparedFile[] = opts.files.map((file) => {
    const count = chunkCountFor(file.size);
    return {
      id: generateFileId(),
      file,
      chunkCount: count,
      ciphertextBytes: ciphertextSize(file.size),
    };
  });
  const note = opts.note?.trim() ? opts.note : null;
  const manifest: Manifest = {
    v: 1,
    createdAt: opts.now ?? Date.now(),
    note,
    files: files.map((f, i) => {
      const src = opts.files[i]!;
      return {
        id: f.id,
        name: clampUnits(src.name || 'file', MAX_FILE_NAME_CHARS),
        size: src.size,
        type: clampUnits(src.type ?? '', MAX_FILE_TYPE_CHARS),
        lastModified: Math.trunc(Number.isFinite(src.lastModified) ? src.lastModified : 0),
        chunkSize: CHUNK_SIZE,
        chunkCount: f.chunkCount,
      };
    }),
  };
  const encryptedManifest = await encryptManifest(dk, manifest);

  const request: CreateDropRequest = {
    encryptedManifest,
    files: files.map((f) => ({
      id: f.id,
      ciphertextBytes: f.ciphertextBytes,
      chunkCount: f.chunkCount,
    })),
    expiresInHours: opts.expiresInHours,
    maxDownloads: opts.maxDownloads,
  };
  if (opts.password) {
    if (!opts.protect) throw new TypeError('prepareDrop: password set without a protect function');
    const p = await opts.protect(dk, opts.password);
    // authKey stays on the client: the server stores only its hash.
    request.password = { kdf: p.kdf, wrappedDropKey: p.wrappedDropKey, authKeyHash: p.authKeyHash };
  }
  if (opts.accountKey) {
    request.ownerWrappedKey = await wrapKey(opts.accountKey, dk, AAD.WRAP_OWNER);
  }
  return { dk, manifest, files, request };
}

/* ---------------------------------------------------------------------------------------------- */
/* Upload (worker)                                                                                 */
/* ---------------------------------------------------------------------------------------------- */

export type UploadEvent =
  | { type: 'chunk-encrypted'; fileId: string; index: number; plainBytes: number }
  | { type: 'chunk-uploaded'; fileId: string; index: number; plainBytes: number }
  | { type: 'cipher-preview'; fileId: string; index: number; hex: string }
  | {
      type: 'retry';
      fileId: string;
      index: number;
      retry: number;
      delayMs: number;
      error: SerializedUploadError;
    }
  | { type: 'file-done'; fileId: string };

export interface UploadOptions {
  dropId: string;
  uploadToken: string;
  dk: Uint8Array;
  files: readonly UploadFileJob[];
  /** Origin for the PUT URLs (workers pass self.location.origin). */
  baseUrl?: string;
  signal?: AbortSignal;
  concurrency?: number;
  delays?: readonly number[];
  sleep?: Sleep;
  onEvent?: (event: UploadEvent) => void;
}

export function chunkPath(dropId: string, fileId: string, index: number): string {
  return `/drops/${encodeURIComponent(dropId)}/files/${encodeURIComponent(fileId)}/chunks/${index}`;
}

/** Plaintext byte range of chunk `index`. */
export function chunkRange(size: number, index: number): { start: number; end: number } {
  const start = index * CHUNK_SIZE;
  return { start, end: Math.min(size, start + CHUNK_SIZE) };
}

/** Read and encrypt chunk `index` of `file` (deterministic: same key, file and index -> same bytes). */
export async function encryptFileChunk(
  key: CryptoKey,
  file: Blob,
  index: number,
  count: number,
): Promise<{ ciphertext: Uint8Array<ArrayBuffer>; plainBytes: number }> {
  const { start, end } = chunkRange(file.size, index);
  const pt = new Uint8Array(await file.slice(start, end).arrayBuffer());
  const ciphertext = await encryptChunk(key, index, index === count - 1, pt);
  return { ciphertext, plainBytes: pt.length };
}

interface ChunkTask {
  job: UploadFileJob;
  index: number;
}

/**
 * Encrypt and PUT every chunk of every file (skipping `skip` indexes). Resolves when all chunks are stored;
 * rejects with the first fatal error (ApiError, crypto error) or an AbortError after cancel.
 */
export async function uploadDropFiles(opts: UploadOptions): Promise<void> {
  const delays = opts.delays ?? UPLOAD_RETRY_DELAYS_MS;
  const internal = new AbortController();
  const onOuterAbort = () => internal.abort();
  if (opts.signal?.aborted) throw abortError();
  opts.signal?.addEventListener('abort', onOuterAbort, { once: true });
  const signal = internal.signal;
  const emit = (e: UploadEvent) => opts.onEvent?.(e);

  const keys = new Map<string, Promise<CryptoKey>>();
  const keyFor = (fileId: string) => {
    let k = keys.get(fileId);
    if (!k) {
      k = deriveFileKey(opts.dk, fileId);
      keys.set(fileId, k);
    }
    return k;
  };

  const tasks: ChunkTask[] = [];
  const remaining = new Map<string, number>();
  for (const job of opts.files) {
    const skip = new Set(job.skip ?? []);
    let pending = 0;
    for (let index = 0; index < job.chunkCount; index++) {
      if (skip.has(index)) continue;
      tasks.push({ job, index });
      pending++;
    }
    remaining.set(job.id, pending);
  }
  // Files the server already has completely are done before anything is sent.
  for (const job of opts.files)
    if (remaining.get(job.id) === 0) emit({ type: 'file-done', fileId: job.id });

  let next = 0;
  let failure: unknown = null;

  const runTask = async ({ job, index }: ChunkTask) => {
    const key = await keyFor(job.id);
    const { ciphertext, plainBytes } = await encryptFileChunk(key, job.file, index, job.chunkCount);
    if (signal.aborted) throw abortError();
    emit({ type: 'chunk-encrypted', fileId: job.id, index, plainBytes });
    emit({
      type: 'cipher-preview',
      fileId: job.id,
      index,
      hex: toHex(ciphertext.subarray(0, CIPHER_PREVIEW_BYTES)),
    });
    const hash = toHex(await sha256(ciphertext));
    await retryWithBackoff(
      () =>
        putBinary(
          chunkPath(opts.dropId, job.id, index),
          ciphertext,
          { [CHUNK_SHA256_HEADER]: hash },
          {
            baseUrl: opts.baseUrl,
            token: opts.uploadToken,
            signal,
          },
        ),
      {
        delays,
        signal,
        sleep: opts.sleep,
        onRetry: (err, retry, delayMs) =>
          emit({
            type: 'retry',
            fileId: job.id,
            index,
            retry,
            delayMs,
            error: serializeUploadError(err),
          }),
      },
    );
    emit({ type: 'chunk-uploaded', fileId: job.id, index, plainBytes });
    const left = (remaining.get(job.id) ?? 1) - 1;
    remaining.set(job.id, left);
    if (left === 0) emit({ type: 'file-done', fileId: job.id });
  };

  const lane = async () => {
    while (failure === null && !signal.aborted) {
      const task = tasks[next++];
      if (!task) return;
      try {
        await runTask(task);
      } catch (err) {
        if (failure === null) failure = err;
        internal.abort();
        return;
      }
    }
  };

  try {
    const width = Math.max(1, Math.min(opts.concurrency ?? UPLOAD_CONCURRENCY, tasks.length || 1));
    await Promise.all(Array.from({ length: width }, lane));
  } finally {
    opts.signal?.removeEventListener('abort', onOuterAbort);
  }
  if (opts.signal?.aborted) throw abortError();
  if (failure !== null) throw failure;
}

/* ---------------------------------------------------------------------------------------------- */
/* Resume check (R11)                                                                              */
/* ---------------------------------------------------------------------------------------------- */

export type ResumeCheck =
  { ok: true; received: Map<string, Set<number>> } | { ok: false; reason: 'mismatch' };

/**
 * Before resuming, prove the re-selected files are the ones the server already holds chunks of: the last
 * received chunk of each file is re-encrypted (STREAM is deterministic per key, index and plaintext) and its
 * SHA-256 compared with upload-status. Any difference, unknown id or chunk-count change -> mismatch.
 */
export async function verifyResume(
  dk: Uint8Array,
  files: readonly UploadFileJob[],
  status: UploadStatus,
): Promise<ResumeCheck> {
  const byId = new Map(files.map((f) => [f.id, f]));
  if (status.files.length !== files.length) return { ok: false, reason: 'mismatch' };
  const received = new Map<string, Set<number>>();
  for (const entry of status.files) {
    const job = byId.get(entry.id);
    if (
      !job ||
      job.chunkCount !== entry.chunkCount ||
      chunkCountFor(job.file.size) !== job.chunkCount
    ) {
      return { ok: false, reason: 'mismatch' };
    }
    const indexes = new Set<number>();
    let last: { index: number; sha256: string } | null = null;
    for (const r of entry.received) {
      if (r.index >= job.chunkCount) return { ok: false, reason: 'mismatch' };
      indexes.add(r.index);
      if (!last || r.index > last.index) last = r;
    }
    if (last) {
      const key = await deriveFileKey(dk, job.id);
      const { ciphertext } = await encryptFileChunk(key, job.file, last.index, job.chunkCount);
      if (toHex(await sha256(ciphertext)) !== last.sha256) return { ok: false, reason: 'mismatch' };
    }
    received.set(job.id, indexes);
  }
  return { ok: true, received };
}

/* ---------------------------------------------------------------------------------------------- */
/* Errors across the worker boundary                                                               */
/* ---------------------------------------------------------------------------------------------- */

export type UploadErrorCode =
  | ApiErrorCode
  | 'INTEGRITY'
  | 'WRONG_PASSWORD'
  | 'KDF_PARAMS'
  | 'INVALID_LINK'
  | 'ABORTED'
  | 'UNKNOWN';

/** Structured-clone-safe error: prototypes and `.code` do not survive postMessage on their own. */
export interface SerializedUploadError {
  code: UploadErrorCode;
  message: string;
  status?: number;
  retryAfter?: number;
}

const CRYPTO_CODES = new Set(['INTEGRITY', 'WRONG_PASSWORD', 'KDF_PARAMS', 'INVALID_LINK']);

export function serializeUploadError(err: unknown): SerializedUploadError {
  if (isApiError(err)) {
    const out: SerializedUploadError = { code: err.code, message: err.message, status: err.status };
    if (err.retryAfter !== undefined) out.retryAfter = err.retryAfter;
    return out;
  }
  if ((err instanceof DOMException || err instanceof Error) && err.name === 'AbortError') {
    return { code: 'ABORTED', message: 'Upload cancelled.' };
  }
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && CRYPTO_CODES.has(code)) {
    return { code: code as UploadErrorCode, message: (err as Error).message };
  }
  // Unknown errors may echo browser internals or file names: never forward their message.
  return { code: 'UNKNOWN', message: 'The upload failed unexpectedly.' };
}

/** Back on the main thread: ApiError (isRetryable works), AbortError, or an Error carrying `.code`. */
export function deserializeUploadError(e: SerializedUploadError): Error {
  if (e.status !== undefined) {
    return new ApiError({
      status: e.status,
      code: e.code as ApiErrorCode,
      message: e.message,
      retryAfter: e.retryAfter,
    });
  }
  if (e.code === 'ABORTED') return abortError() as unknown as Error;
  const err = new Error(e.message) as Error & { code: string };
  err.name = e.code === 'INTEGRITY' ? 'IntegrityError' : 'UploadError';
  err.code = e.code;
  return err;
}
