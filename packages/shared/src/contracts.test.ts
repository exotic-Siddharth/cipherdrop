import { describe, expect, it } from 'vitest';
import {
  AUDIT_ACTION_LABELS,
  AuditActionSchema,
  B64Url16Schema,
  B64Url32Schema,
  CHUNK_SHA256_HEADER,
  CreateDropRequestSchema,
  DOWNLOAD_OPTIONS,
  ErrorBodySchema,
  EXPIRY_OPTIONS,
  KdfParamsSchema,
  LIMITS,
  LoginResponseSchema,
  MeDropsQuerySchema,
  OwnerDropSummarySchema,
  RecoveryRotateRequestSchema,
  SHA256_HEX_RE,
  UploadStatusSchema,
  WrappedKeySchema,
  pageSchema,
} from './index';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** Distinct canonical b64url(16 bytes) ids: varying first char, canonical last char 'A'. */
const fileId = (i: number) => `${B64[i]}${'A'.repeat(20)}A`;
const key32 = 'A'.repeat(42) + 'A';
const wrapped = 'w'.repeat(80);
const kdf = { salt: 'AAECAwQFBgcICQoLDA0ODw', memoryKiB: 65536, iterations: 3, parallelism: 1 };

const me = {
  id: 'cmuser0000000000000000000',
  email: 'demo@cipherdrop.local',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 5368709120,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
};

function createDrop(overrides: Record<string, unknown> = {}) {
  return {
    encryptedManifest: 'A'.repeat(120),
    files: [{ id: fileId(0), ciphertextBytes: 1016, chunkCount: 1 }],
    expiresInHours: 24,
    maxDownloads: 1,
    ...overrides,
  };
}

describe('CreateDropRequestSchema', () => {
  it('accepts a minimal valid anonymous drop', () => {
    expect(CreateDropRequestSchema.safeParse(createDrop()).success).toBe(true);
  });

  it('rejects 21 files', () => {
    const files = Array.from({ length: 21 }, (_, i) => ({
      id: fileId(i),
      ciphertextBytes: 16,
      chunkCount: 1,
    }));
    const result = CreateDropRequestSchema.safeParse(createDrop({ files }));
    expect(result.success).toBe(false);
    // 20 files is the ceiling and is accepted.
    expect(
      CreateDropRequestSchema.safeParse(createDrop({ files: files.slice(0, 20) })).success,
    ).toBe(true);
  });

  it('rejects expiresInHours 0', () => {
    expect(CreateDropRequestSchema.safeParse(createDrop({ expiresInHours: 0 })).success).toBe(
      false,
    );
    expect(CreateDropRequestSchema.safeParse(createDrop({ expiresInHours: 1 })).success).toBe(true);
  });

  it('accepts only the listed download limits', () => {
    for (const n of DOWNLOAD_OPTIONS) {
      expect(CreateDropRequestSchema.safeParse(createDrop({ maxDownloads: n })).success).toBe(true);
    }
    expect(CreateDropRequestSchema.safeParse(createDrop({ maxDownloads: 4 })).success).toBe(false);
  });

  it('rejects duplicate file ids and inconsistent chunkCount/ciphertextBytes', () => {
    const dup = [
      { id: fileId(1), ciphertextBytes: 16, chunkCount: 1 },
      { id: fileId(1), ciphertextBytes: 16, chunkCount: 1 },
    ];
    expect(CreateDropRequestSchema.safeParse(createDrop({ files: dup })).success).toBe(false);
    // 2 chunks need at least CHUNK_SIZE + 1 plaintext bytes, i.e. CHUNK_SIZE + 1 + 32 ciphertext bytes.
    const tooSmall = [{ id: fileId(2), ciphertextBytes: LIMITS.CHUNK_SIZE + 32, chunkCount: 2 }];
    expect(CreateDropRequestSchema.safeParse(createDrop({ files: tooSmall })).success).toBe(false);
    const ok = [{ id: fileId(2), ciphertextBytes: LIMITS.CHUNK_SIZE + 33, chunkCount: 2 }];
    expect(CreateDropRequestSchema.safeParse(createDrop({ files: ok })).success).toBe(true);
    const tooBig = [{ id: fileId(3), ciphertextBytes: LIMITS.MAX_CHUNK_BYTES + 1, chunkCount: 1 }];
    expect(CreateDropRequestSchema.safeParse(createDrop({ files: tooBig })).success).toBe(false);
  });

  it('rejects an oversized files array without validating every element (zod 3 memory-DoS guard)', () => {
    const result = CreateDropRequestSchema.safeParse(createDrop({ files: Array(200_000).fill(1) }));
    expect(result.success).toBe(false);
    // Without the guard zod 3 reports one issue per element (200 000+); with it, at most max+1 elements are parsed.
    expect(result.error?.issues.length).toBeLessThanOrEqual(LIMITS.MAX_FILES_PER_DROP + 2);
  });

  it('accepts password protection and an owner-wrapped key', () => {
    const body = createDrop({
      password: { kdf, wrappedDropKey: wrapped, authKeyHash: key32 },
      ownerWrappedKey: wrapped,
    });
    expect(CreateDropRequestSchema.safeParse(body).success).toBe(true);
  });
});

describe('LoginResponseSchema', () => {
  it('discriminates mfaRequired', () => {
    const ok = LoginResponseSchema.parse({ mfaRequired: false, user: me, accessToken: 'jwt' });
    expect(ok.mfaRequired).toBe(false);
    if (!ok.mfaRequired) expect(ok.user.email).toBe('demo@cipherdrop.local');

    const mfa = LoginResponseSchema.parse({ mfaRequired: true, mfaToken: 'purpose-jwt' });
    expect(mfa.mfaRequired).toBe(true);
    if (mfa.mfaRequired) expect(mfa.mfaToken).toBe('purpose-jwt');

    expect(LoginResponseSchema.safeParse({ mfaRequired: true }).success).toBe(false);
    expect(LoginResponseSchema.safeParse({ mfaRequired: false, mfaToken: 'x' }).success).toBe(
      false,
    );
  });
});

describe('primitives', () => {
  it('base64url schemas accept only canonical encodings of the exact length', () => {
    expect(B64Url32Schema.safeParse(key32).success).toBe(true);
    expect(B64Url32Schema.safeParse('A'.repeat(42) + 'B').success).toBe(false); // non-canonical tail
    expect(B64Url32Schema.safeParse('A'.repeat(42)).success).toBe(false);
    expect(B64Url32Schema.safeParse('A'.repeat(42) + '=').success).toBe(false);
    expect(B64Url16Schema.safeParse('AAECAwQFBgcICQoLDA0ODw').success).toBe(true);
    expect(B64Url16Schema.safeParse('AAECAwQFBgcICQoLDA0ODx').success).toBe(false);
    expect(WrappedKeySchema.safeParse(wrapped).success).toBe(true);
    expect(WrappedKeySchema.safeParse(wrapped.slice(1)).success).toBe(false);
  });

  it('KdfParamsSchema enforces KDF_MIN/KDF_MAX', () => {
    expect(KdfParamsSchema.safeParse(kdf).success).toBe(true);
    expect(KdfParamsSchema.safeParse({ ...kdf, memoryKiB: 1024 }).success).toBe(false);
    expect(KdfParamsSchema.safeParse({ ...kdf, iterations: 1 }).success).toBe(false);
    expect(KdfParamsSchema.safeParse({ ...kdf, memoryKiB: 262145 }).success).toBe(false);
  });

  it('error bodies and pages have the conventional shape', () => {
    expect(
      ErrorBodySchema.safeParse({
        error: { code: 'GONE', message: 'x', details: { reason: 'EXPIRED' } },
      }).success,
    ).toBe(true);
    expect(ErrorBodySchema.safeParse({ error: { code: 'NOPE', message: 'x' } }).success).toBe(
      false,
    );
    const page = pageSchema(OwnerDropSummarySchema);
    expect(page.safeParse({ items: [], total: 0, page: 1, pageSize: 20 }).success).toBe(true);
  });
});

describe('R5/R6/R9/R11 contracts', () => {
  it('exports the chunk hash header and hex pattern', () => {
    expect(CHUNK_SHA256_HEADER).toBe('x-chunk-sha256');
    expect(SHA256_HEX_RE.test('a'.repeat(64))).toBe(true);
    expect(SHA256_HEX_RE.test('A'.repeat(64))).toBe(false);
  });

  it('me/drops status defaults to active', () => {
    expect(MeDropsQuerySchema.parse({})).toEqual({ status: 'active', page: 1, pageSize: 20 });
    expect(MeDropsQuerySchema.safeParse({ status: 'deleted' }).success).toBe(false);
  });

  it('recovery rotate body and upload-status with sha256', () => {
    expect(
      RecoveryRotateRequestSchema.safeParse({
        authKey: key32,
        wrappedAccountKeyRecovery: wrapped,
        recoveryAuthHash: key32,
      }).success,
    ).toBe(true);
    expect(
      UploadStatusSchema.safeParse({
        files: [{ id: fileId(0), chunkCount: 1, received: [{ index: 0, sha256: 'f'.repeat(64) }] }],
      }).success,
    ).toBe(true);
  });
});

describe('UI constants', () => {
  it('labels every audit action and offers anon-safe options', () => {
    for (const action of AuditActionSchema.options) {
      expect(AUDIT_ACTION_LABELS[action]).toMatch(/\S/);
    }
    expect(
      EXPIRY_OPTIONS.filter((o) => o.anon).every((o) => o.hours <= LIMITS.ANON_MAX_EXPIRY_HOURS),
    ).toBe(true);
    expect(DOWNLOAD_OPTIONS).toEqual([1, 2, 3, 5, 10, 20, 50, 100]);
  });
});
