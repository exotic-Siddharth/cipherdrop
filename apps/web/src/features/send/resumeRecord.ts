/**
 * Upload-resume record (R11), kept in sessionStorage so a reload in the same tab can resume an interrupted
 * upload. It holds NO file names, types or notes: files are matched again by size + lastModified when the
 * user re-selects them. Cleared on complete, cancel, mismatch and expiry.
 *
 * R11 fields: dropId, uploadToken, dk (b64url), files [{id, size, lastModified, chunkCount}]. Display-only
 * additions (2026-11-08 decision): ownerToken (Delete now / Sent from this device), expiresAt, maxDownloads,
 * passwordProtected, anonymous and createdAt.
 */

export const RESUME_STORAGE_KEY = 'cd-upload-resume';
/** UPLOADING drops are cleaned up server-side after 24 h (spec 9). */
const STALE_UPLOAD_MS = 24 * 3_600_000;

export interface ResumeFile {
  id: string;
  size: number;
  lastModified: number;
  chunkCount: number;
}

export interface ResumeRecord {
  dropId: string;
  uploadToken: string;
  /** b64url(DK) */
  dk: string;
  files: ResumeFile[];
  ownerToken: string;
  expiresAt: string;
  createdAt: string;
  maxDownloads: number;
  passwordProtected: boolean;
  anonymous: boolean;
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function isNonNegInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

function isResumeRecord(v: unknown): v is ResumeRecord {
  if (!v || typeof v !== 'object') return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r.dropId === 'string' &&
    B64URL_RE.test(r.dropId) &&
    typeof r.uploadToken === 'string' &&
    B64URL_RE.test(r.uploadToken) &&
    typeof r.dk === 'string' &&
    r.dk.length === 43 &&
    B64URL_RE.test(r.dk) &&
    typeof r.ownerToken === 'string' &&
    typeof r.expiresAt === 'string' &&
    typeof r.createdAt === 'string' &&
    isNonNegInt(r.maxDownloads) &&
    typeof r.passwordProtected === 'boolean' &&
    typeof r.anonymous === 'boolean' &&
    Array.isArray(r.files) &&
    r.files.length > 0 &&
    r.files.every((f: unknown) => {
      const x = f as Record<string, unknown>;
      return (
        !!x &&
        typeof x.id === 'string' &&
        B64URL_RE.test(x.id) &&
        isNonNegInt(x.size) &&
        typeof x.lastModified === 'number' &&
        isNonNegInt(x.chunkCount)
      );
    })
  );
}

/** The live record, or null (missing, corrupt, expired or stale records are removed). */
export function readResumeRecord(now: number = Date.now()): ResumeRecord | null {
  try {
    const raw = window.sessionStorage.getItem(RESUME_STORAGE_KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!isResumeRecord(parsed)) {
      clearResumeRecord();
      return null;
    }
    const expires = Math.min(
      Date.parse(parsed.expiresAt),
      Date.parse(parsed.createdAt) + STALE_UPLOAD_MS,
    );
    if (!(expires > now)) {
      clearResumeRecord();
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function writeResumeRecord(record: ResumeRecord): void {
  const clean: ResumeRecord = {
    dropId: record.dropId,
    uploadToken: record.uploadToken,
    dk: record.dk,
    files: record.files.map((f) => ({
      id: f.id,
      size: f.size,
      lastModified: f.lastModified,
      chunkCount: f.chunkCount,
    })),
    ownerToken: record.ownerToken,
    expiresAt: record.expiresAt,
    createdAt: record.createdAt,
    maxDownloads: record.maxDownloads,
    passwordProtected: record.passwordProtected,
    anonymous: record.anonymous,
  };
  try {
    window.sessionStorage.setItem(RESUME_STORAGE_KEY, JSON.stringify(clean));
  } catch {
    // Storage blocked: resume after reload is simply unavailable.
  }
}

export function clearResumeRecord(): void {
  try {
    window.sessionStorage.removeItem(RESUME_STORAGE_KEY);
  } catch {
    // ignore
  }
}

/**
 * Match re-selected files to the record by size + lastModified (each file used once). Returns the files in
 * record order, or null unless every record file matches and nothing extra was selected.
 */
export function matchResumeFiles<F extends { size: number; lastModified: number }>(
  record: ResumeRecord,
  selected: readonly F[],
): F[] | null {
  if (selected.length !== record.files.length) return null;
  const pool = [...selected];
  const out: F[] = [];
  for (const rf of record.files) {
    const i = pool.findIndex((f) => f.size === rf.size && f.lastModified === rf.lastModified);
    if (i === -1) return null;
    out.push(pool[i]!);
    pool.splice(i, 1);
  }
  return out;
}
