/**
 * Limits, option lists, header names and UI labels shared by the API and the SPA (spec sections 6, 9-11).
 *
 * Byte limits here are the spec defaults; the API's env (ANON_MAX_DROP_BYTES, ...) is authoritative at runtime.
 */
import {
  CHUNK_SIZE,
  MAX_ENCRYPTED_MANIFEST_CHARS,
  MAX_FILES_PER_DROP,
  MAX_NOTE_CHARS,
  TAG_BYTES,
} from '@cipherdrop/crypto/constants';
import type { AuditAction } from './common';

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

export const LIMITS = Object.freeze({
  CHUNK_SIZE,
  TAG_BYTES,
  /** Non-final ciphertext chunks are exactly this size; the final one is 16..this. */
  MAX_CHUNK_BYTES: CHUNK_SIZE + TAG_BYTES,
  MIN_CHUNK_BYTES: TAG_BYTES,
  MAX_FILES_PER_DROP,
  MAX_NOTE_CHARS,
  MAX_ENCRYPTED_MANIFEST_CHARS,
  /** Ciphertext bytes per anonymous drop (100 MiB). */
  ANON_MAX_DROP_BYTES: 100 * MiB,
  /** Ciphertext bytes per user drop (2 GiB). */
  USER_MAX_DROP_BYTES: 2 * GiB,
  USER_DEFAULT_QUOTA_BYTES: 5 * GiB,
  ANON_MAX_EXPIRY_HOURS: 72,
  USER_MAX_EXPIRY_HOURS: 720,
  ANON_MAX_DOWNLOADS: 10,
  MAX_REPORT_DETAILS_CHARS: 1000,
  /** express.json limit for every JSON body. */
  JSON_BODY_LIMIT: '1mb',
  BACKUP_CODE_COUNT: 10,
  /** UPLOADING drops older than this are cleaned up. */
  STALE_UPLOAD_HOURS: 24,
  /** A download grant never lives longer than this after it was created (R12). */
  GRANT_MAX_LIFETIME_HOURS: 24,
  /** Receive page: files up to this size are saved through a Blob, larger ones through showSaveFilePicker. */
  BLOB_SAVE_MAX_BYTES: 256 * 1024 * 1024,
});

/** `maxDownloads` choices; 1 = burn after reading. Anonymous drops allow at most ANON_MAX_DOWNLOADS. */
export const DOWNLOAD_OPTIONS = [1, 2, 3, 5, 10, 20, 50, 100] as const;
export type DownloadOption = (typeof DOWNLOAD_OPTIONS)[number];
export const ANON_MAX_DOWNLOADS = LIMITS.ANON_MAX_DOWNLOADS;

export function downloadOptionsFor(kind: 'anon' | 'user'): DownloadOption[] {
  return DOWNLOAD_OPTIONS.filter((n) => kind === 'user' || n <= ANON_MAX_DOWNLOADS);
}

export interface ExpiryOption {
  hours: number;
  label: string;
  /** Offered to anonymous senders (<= ANON_MAX_EXPIRY_HOURS). */
  anon: boolean;
  /** Offered to signed-in senders (<= USER_MAX_EXPIRY_HOURS). */
  user: boolean;
}

/** Expiry choices shown by the Send page; the API accepts any whole hour within the caller's ceiling. */
export const EXPIRY_OPTIONS: readonly ExpiryOption[] = Object.freeze([
  { hours: 1, label: '1 hour', anon: true, user: true },
  { hours: 6, label: '6 hours', anon: true, user: true },
  { hours: 24, label: '1 day', anon: true, user: true },
  { hours: 72, label: '3 days', anon: true, user: true },
  { hours: 168, label: '7 days', anon: false, user: true },
  { hours: 336, label: '14 days', anon: false, user: true },
  { hours: 720, label: '30 days', anon: false, user: true },
]);

export function expiryOptionsFor(kind: 'anon' | 'user'): ExpiryOption[] {
  return EXPIRY_OPTIONS.filter((o) => (kind === 'anon' ? o.anon : o.user));
}

/** Vault auto-lock choices in minutes (spec section 7.5). */
export const AUTO_LOCK_OPTIONS = [5, 15, 60] as const;
export type AutoLockMinutes = (typeof AUTO_LOCK_OPTIONS)[number];
export const DEFAULT_AUTO_LOCK_MINUTES: AutoLockMinutes = 15;

/** Human text per audit action (Activity tab). The UI appends the IP prefix and UA summary. */
export const AUDIT_ACTION_LABELS: Readonly<Record<AuditAction, string>> = Object.freeze({
  REGISTER: 'Account created',
  LOGIN_SUCCESS: 'Signed in',
  LOGIN_FAILURE: 'Failed sign-in attempt',
  LOGIN_LOCKED: 'Account temporarily locked after failed sign-ins',
  MFA_CHALLENGE_FAILED: 'Wrong two-factor code',
  MFA_ENABLED: 'Two-factor authentication enabled',
  MFA_DISABLED: 'Two-factor authentication disabled',
  BACKUP_CODE_USED: 'Backup code used',
  BACKUP_CODES_REGENERATED: 'Backup codes regenerated',
  PASSWORD_CHANGED: 'Password changed',
  RECOVERY_USED: 'Account recovered with the recovery key',
  RECOVERY_KEY_ROTATED: 'Recovery key replaced',
  SESSION_REVOKED: 'Session signed out',
  SESSION_REUSE_DETECTED: 'Refresh token reuse detected, session revoked',
  LOGOUT: 'Signed out',
  ACCOUNT_DELETED: 'Account deleted',
  DROP_CREATED: 'Drop created',
  DROP_COMPLETED: 'Drop upload completed',
  DROP_OPENED: 'Your drop was downloaded',
  DROP_UNLOCK_FAILED: 'Wrong password entered for your drop',
  DROP_DELETED: 'Drop deleted',
  DROP_EXPIRED: 'Drop expired',
  DROP_EXHAUSTED: 'Drop reached its download limit',
  DROP_REPORTED: 'Drop reported for abuse',
  DROP_DISABLED: 'Drop disabled by a moderator',
});

/* ---- Wire details ---- */

export const API_PREFIX = '/api';
/** R5: lowercase hex SHA-256 of the ciphertext chunk, sent with every chunk PUT. */
export const CHUNK_SHA256_HEADER = 'x-chunk-sha256';
export const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
/** Owner token header for DELETE /api/drops/:id (anonymous owners). */
export const OWNER_TOKEN_HEADER = 'x-owner-token';
/** Refresh-token cookie (httpOnly, SameSite=Strict, Path=/api/auth, Secure in prod). */
export const REFRESH_COOKIE_NAME = 'cd_rt';
export const REFRESH_COOKIE_PATH = '/api/auth';
export const REQUEST_ID_HEADER = 'x-request-id';
