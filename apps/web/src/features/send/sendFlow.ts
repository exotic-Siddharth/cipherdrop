/**
 * Send orchestration on the main thread (spec 11.3; R7, R11):
 *   prepareDrop (DK, ids, encrypted manifest, password wrap in kdf.worker, owner wrap) -> POST /drops
 *   -> resume record -> upload.worker (encrypt + PUT) -> POST complete -> clear the record.
 * resumeDrop() continues an interrupted upload after a reload, once the R11 hash check passed.
 */
import { b64urlDecode, b64urlEncode, chunkCount, ciphertextSize } from '@cipherdrop/crypto';
import {
  CompleteConflictDetailsSchema,
  CompleteDropResponseSchema,
  CreateDropResponseSchema,
  OWNER_TOKEN_HEADER,
  UploadStatusSchema,
  type DownloadOption,
} from '@cipherdrop/shared';
import { kdfClient } from '../../crypto/kdfClient';
import {
  chunkRange,
  prepareDrop,
  verifyResume,
  type UploadEvent,
  type UploadFileJob,
} from '../../crypto/uploader';
import { api, isApiError } from '../../lib/api';
import { clearResumeRecord, writeResumeRecord, type ResumeRecord } from './resumeRecord';
import { runUploadInWorker } from './uploadClient';

export type SendPhase =
  'preparing' | 'deriving' | 'creating' | 'checking' | 'uploading' | 'completing';

export interface SendCallbacks {
  onPhase?: (phase: SendPhase) => void;
  onEvent?: (event: UploadEvent) => void;
  /** The drop exists server-side (Cancel can delete it from here on). */
  onCreated?: (record: ResumeRecord) => void;
}

export interface SendResult {
  dropId: string;
  /** DK: only used to build the link (null in the link for password drops). */
  dk: Uint8Array;
  ownerToken: string;
  expiresAt: string;
  createdAt: string;
  maxDownloads: number;
  passwordProtected: boolean;
  anonymous: boolean;
  fileCount: number;
  /** Plaintext bytes. */
  totalBytes: number;
}

export interface NewDropInput {
  files: readonly File[];
  note: string;
  expiresInHours: number;
  maxDownloads: DownloadOption;
  password: string | null;
  /** Signed in: the unlocked vault key (owner wrap computed before the upload starts, R7). */
  accountKey: CryptoKey | null;
  anonymous: boolean;
}

function origin(): string {
  return window.location.origin;
}

async function completeWithRepair(
  record: ResumeRecord,
  jobs: UploadFileJob[],
  dk: Uint8Array,
  cb: SendCallbacks,
  signal?: AbortSignal,
): Promise<void> {
  cb.onPhase?.('completing');
  const complete = () =>
    api.post(`/drops/${encodeURIComponent(record.dropId)}/complete`, undefined, {
      token: record.uploadToken,
      schema: CompleteDropResponseSchema,
      signal,
    });
  try {
    await complete();
  } catch (err) {
    // 409 with the missing chunks: upload exactly those once more, then complete again.
    if (!isApiError(err) || err.status !== 409) throw err;
    const details = CompleteConflictDetailsSchema.safeParse(err.details);
    if (!details.success || details.data.missing.length === 0) throw err;
    const missing = new Map(details.data.missing.map((m) => [m.fileId, new Set(m.indexes)]));
    const repair = jobs.map((j) => {
      const want = missing.get(j.id) ?? new Set<number>();
      const skip: number[] = [];
      for (let i = 0; i < j.chunkCount; i++) if (!want.has(i)) skip.push(i);
      return { ...j, skip };
    });
    cb.onPhase?.('uploading');
    await runUploadInWorker(
      {
        dropId: record.dropId,
        uploadToken: record.uploadToken,
        dk,
        files: repair,
        baseUrl: origin(),
      },
      (e) => cb.onEvent?.(e),
      signal,
    );
    cb.onPhase?.('completing');
    await complete();
  }
}

function resultFrom(record: ResumeRecord, dk: Uint8Array, files: readonly File[]): SendResult {
  return {
    dropId: record.dropId,
    dk,
    ownerToken: record.ownerToken,
    expiresAt: record.expiresAt,
    createdAt: record.createdAt,
    maxDownloads: record.maxDownloads,
    passwordProtected: record.passwordProtected,
    anonymous: record.anonymous,
    fileCount: files.length,
    totalBytes: files.reduce((n, f) => n + f.size, 0),
  };
}

export async function startNewDrop(
  input: NewDropInput,
  cb: SendCallbacks = {},
  signal?: AbortSignal,
): Promise<SendResult> {
  cb.onPhase?.(input.password ? 'deriving' : 'preparing');
  const prepared = await prepareDrop({
    files: input.files,
    note: input.note,
    expiresInHours: input.expiresInHours,
    maxDownloads: input.maxDownloads,
    password: input.password,
    protect: (dk, pw) => kdfClient.createPasswordProtection(dk, pw),
    accountKey: input.anonymous ? null : input.accountKey,
  });
  if (signal?.aborted) throw new DOMException('The operation was aborted.', 'AbortError');

  cb.onPhase?.('creating');
  const created = await api.post('/drops', prepared.request, {
    schema: CreateDropResponseSchema,
    anonymous: input.anonymous,
    signal,
  });
  const record: ResumeRecord = {
    dropId: created.dropId,
    uploadToken: created.uploadToken,
    dk: b64urlEncode(prepared.dk),
    files: prepared.files.map((f, i) => ({
      id: f.id,
      size: input.files[i]!.size,
      lastModified: input.files[i]!.lastModified,
      chunkCount: f.chunkCount,
    })),
    ownerToken: created.ownerToken,
    expiresAt: created.expiresAt,
    createdAt: new Date().toISOString(),
    maxDownloads: input.maxDownloads,
    passwordProtected: Boolean(input.password),
    anonymous: input.anonymous,
  };
  writeResumeRecord(record);
  cb.onCreated?.(record);

  cb.onPhase?.('uploading');
  const jobs: UploadFileJob[] = prepared.files.map((f) => ({
    id: f.id,
    file: f.file,
    chunkCount: f.chunkCount,
  }));
  await runUploadInWorker(
    {
      dropId: record.dropId,
      uploadToken: record.uploadToken,
      dk: prepared.dk,
      files: jobs,
      baseUrl: origin(),
    },
    (e) => cb.onEvent?.(e),
    signal,
  );
  await completeWithRepair(record, jobs, prepared.dk, cb, signal);
  clearResumeRecord();
  return resultFrom(record, prepared.dk, input.files);
}

/** Jobs for a resume: the record's ids in record order, bound to the re-selected (matched) files. */
export function resumeJobs(record: ResumeRecord, files: readonly File[]): UploadFileJob[] {
  return record.files.map((rf, i) => ({ id: rf.id, file: files[i]!, chunkCount: rf.chunkCount }));
}

/**
 * Continue an interrupted upload (R11). `files` must be matched to the record (matchResumeFiles), in
 * record order. Returns 'mismatch' when the server's chunks do not belong to these files or the drop is no
 * longer uploading: the caller then abandons the record and starts a fresh drop.
 */
export async function resumeDrop(
  record: ResumeRecord,
  files: readonly File[],
  cb: SendCallbacks = {},
  signal?: AbortSignal,
): Promise<SendResult | 'mismatch'> {
  cb.onPhase?.('checking');
  const dk = b64urlDecode(record.dk);
  const jobs = resumeJobs(record, files);
  if (jobs.some((j) => chunkCount(j.file.size) !== j.chunkCount)) return 'mismatch';
  let status;
  try {
    status = await api.get(`/drops/${encodeURIComponent(record.dropId)}/upload-status`, {
      token: record.uploadToken,
      schema: UploadStatusSchema,
      signal,
    });
  } catch (err) {
    // The drop is gone, completed or the token is no longer valid: start over.
    if (isApiError(err) && [401, 403, 404, 409, 410].includes(err.status)) return 'mismatch';
    throw err;
  }
  const check = await verifyResume(dk, jobs, status);
  if (!check.ok) return 'mismatch';
  cb.onCreated?.(record);
  const withSkip = jobs.map((j) => ({ ...j, skip: [...(check.received.get(j.id) ?? [])] }));
  for (const j of withSkip) {
    for (const index of j.skip) {
      const { start, end } = chunkRange(j.file.size, index);
      const plainBytes = end - start;
      cb.onEvent?.({ type: 'chunk-encrypted', fileId: j.id, index, plainBytes });
      cb.onEvent?.({ type: 'chunk-uploaded', fileId: j.id, index, plainBytes });
    }
  }
  cb.onPhase?.('uploading');
  await runUploadInWorker(
    {
      dropId: record.dropId,
      uploadToken: record.uploadToken,
      dk,
      files: withSkip,
      baseUrl: origin(),
    },
    (e) => cb.onEvent?.(e),
    signal,
  );
  await completeWithRepair(record, jobs, dk, cb, signal);
  clearResumeRecord();
  return resultFrom(record, dk, files);
}

/** Best-effort delete with the owner token (Cancel, Delete now, Sent from this device). */
export async function deleteDrop(dropId: string, ownerToken: string | null): Promise<void> {
  try {
    await api.delete(`/drops/${encodeURIComponent(dropId)}`, undefined, {
      headers: ownerToken ? { [OWNER_TOKEN_HEADER]: ownerToken } : undefined,
    });
  } catch (err) {
    // Already gone counts as deleted.
    if (isApiError(err) && (err.status === 404 || err.status === 410)) return;
    throw err;
  }
}

/** Ciphertext bytes the server will count against the per-drop limit. */
export function dropCiphertextBytes(files: readonly { size: number }[]): number {
  return files.reduce((n, f) => n + ciphertextSize(f.size), 0);
}
