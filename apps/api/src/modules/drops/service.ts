/**
 * Drops business logic (spec sections 9 and 10 "Drops", R5, R7, R11, R12). Route handlers in routes.ts stay
 * thin: they verify tokens, apply limiters and call these functions.
 *
 * Zero knowledge: the server stores and returns opaque blobs (encryptedManifest, wrapped keys) verbatim and
 * never logs them, never puts them in errors or audit metadata. Tokens are stored as sha256B64url only.
 */
import {
  LIMITS,
  type CompleteConflictDetails,
  type CreateDropRequest,
  type CreateDropResponse,
  type DropMeta,
  type OpenResponse,
  type UploadStatus,
} from '@cipherdrop/shared';
import { Prisma, type Drop } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import type { Request } from 'express';
import type { AppContext } from '../../context';
import {
  conflict,
  forbidden,
  gone,
  notFound,
  payloadTooLarge,
  quotaExceeded,
  unauthorized,
  validationError,
} from '../../lib/errors';
import { decodeB64url, sha256B64url, timingSafeEqualStr } from '../../lib/hash';
import { ipPrefix } from '../../lib/ip';
import { metrics } from '../../lib/metrics';
import { randomToken } from '../../lib/tokens';
import type { AuthUser } from '../../types/express';
import { downloadsRemaining, goneReason, purgeDropBlobs } from './lifecycle';

const HOUR_MS = 3_600_000;
const MIN_MS = 60_000;

type Req = Pick<Request, 'ip' | 'headers'>;

/* ---------------------------------------------------------------- tokens */

/** Drop whose upload token matches `token` (constant-time), or a 401. Unknown drops get the same 401. */
export async function dropForUploadToken(
  ctx: AppContext,
  dropId: string,
  token: string | null,
): Promise<Drop> {
  if (!token) throw unauthorized();
  const hash = sha256B64url(token);
  const drop = await ctx.prisma.drop.findUnique({ where: { id: dropId } });
  if (!drop) {
    timingSafeEqualStr(hash, hash);
    throw unauthorized();
  }
  if (!timingSafeEqualStr(drop.uploadTokenHash, hash)) throw unauthorized();
  return drop;
}

/** The chunk ciphertext size the client must send for `index` (spec section 9: exact sizes). */
export function expectedChunkSize(
  file: { chunkCount: number; ciphertextBytes: bigint },
  index: number,
): number {
  const full = LIMITS.MAX_CHUNK_BYTES;
  if (index < file.chunkCount - 1) return full;
  return Number(file.ciphertextBytes) - (file.chunkCount - 1) * full;
}

/* ---------------------------------------------------------------- create */

export async function createDrop(
  ctx: AppContext,
  body: CreateDropRequest,
  user: AuthUser | undefined,
  req: Req,
): Promise<CreateDropResponse> {
  const { env } = ctx;
  const anon = !user;
  if (body.files.length > env.MAX_FILES_PER_DROP) {
    throw validationError(`At most ${env.MAX_FILES_PER_DROP} files per drop`);
  }
  if (anon) {
    if (body.ownerWrappedKey) throw validationError('ownerWrappedKey requires a signed-in sender');
    if (body.maxDownloads > LIMITS.ANON_MAX_DOWNLOADS) {
      throw validationError(`Anonymous drops allow at most ${LIMITS.ANON_MAX_DOWNLOADS} downloads`);
    }
    if (body.expiresInHours > env.ANON_MAX_EXPIRY_HOURS) {
      throw validationError(
        `Anonymous drops expire after at most ${env.ANON_MAX_EXPIRY_HOURS} hours`,
      );
    }
  } else {
    // R7: a signed-in sender always stores the owner wrap, so the dashboard can rebuild links.
    if (!body.ownerWrappedKey) throw validationError('ownerWrappedKey is required when signed in');
    if (body.expiresInHours > env.USER_MAX_EXPIRY_HOURS) {
      throw validationError(`Drops expire after at most ${env.USER_MAX_EXPIRY_HOURS} hours`);
    }
  }

  const totalBytes = body.files.reduce((sum, f) => sum + f.ciphertextBytes, 0);
  const maxBytes = anon ? env.ANON_MAX_DROP_BYTES : env.USER_MAX_DROP_BYTES;
  if (totalBytes > maxBytes) {
    throw payloadTooLarge('The drop is larger than allowed', { maxBytes });
  }

  if (user) {
    const owner = await ctx.prisma.user.findUnique({
      where: { id: user.id },
      select: { storageQuotaBytes: true, storageUsedBytes: true },
    });
    if (!owner) throw unauthorized();
    // Pending uploads count too, so parallel uploads cannot overshoot the quota.
    const pending = await ctx.prisma.drop.aggregate({
      _sum: { totalCiphertextBytes: true },
      where: { ownerId: user.id, status: 'UPLOADING' },
    });
    const committed = owner.storageUsedBytes + (pending._sum.totalCiphertextBytes ?? 0n);
    if (committed + BigInt(totalBytes) > owner.storageQuotaBytes) {
      throw quotaExceeded('Storage quota exceeded', {
        quotaBytes: Number(owner.storageQuotaBytes),
        usedBytes: Number(committed),
      });
    }
  }

  const now = ctx.now();
  const id = randomBytes(16).toString('base64url');
  const ownerToken = randomToken();
  const uploadToken = randomToken();
  const expiresAt = new Date(now.getTime() + body.expiresInHours * HOUR_MS);
  const pw = body.password;

  await ctx.prisma.drop.create({
    data: {
      id,
      ownerId: user?.id ?? null,
      ownerTokenHash: sha256B64url(ownerToken),
      uploadTokenHash: sha256B64url(uploadToken),
      encryptedManifest: body.encryptedManifest,
      ownerWrappedKey: body.ownerWrappedKey ?? null,
      passwordProtected: Boolean(pw),
      pwKdfSalt: pw?.kdf.salt ?? null,
      pwKdfMemoryKiB: pw?.kdf.memoryKiB ?? null,
      pwKdfIterations: pw?.kdf.iterations ?? null,
      pwKdfParallelism: pw?.kdf.parallelism ?? null,
      wrappedDropKey: pw?.wrappedDropKey ?? null,
      authKeyHash: pw?.authKeyHash ?? null,
      totalCiphertextBytes: BigInt(totalBytes),
      fileCount: body.files.length,
      maxDownloads: body.maxDownloads,
      expiresAt,
      createdAt: now,
      files: {
        create: body.files.map((f) => ({
          id: f.id,
          ciphertextBytes: BigInt(f.ciphertextBytes),
          chunkCount: f.chunkCount,
        })),
      },
    },
  });

  metrics.dropsCreated.inc({ anon: anon ? 'true' : 'false' });
  if (user) await ctx.audit.record({ userId: user.id, dropId: id, action: 'DROP_CREATED', req });
  return { dropId: id, ownerToken, uploadToken, expiresAt: expiresAt.toISOString() };
}

/* ---------------------------------------------------------------- upload */

export async function uploadStatus(ctx: AppContext, drop: Drop): Promise<UploadStatus> {
  if (drop.status !== 'UPLOADING') throw conflict('This drop is no longer accepting uploads');
  const [files, chunks] = await Promise.all([
    ctx.prisma.dropFile.findMany({ where: { dropId: drop.id }, orderBy: { id: 'asc' } }),
    ctx.prisma.dropChunk.findMany({
      where: { dropId: drop.id },
      orderBy: [{ fileId: 'asc' }, { index: 'asc' }],
      select: { fileId: true, index: true, sha256: true },
    }),
  ]);
  return {
    files: files.map((f) => ({
      id: f.id,
      chunkCount: f.chunkCount,
      received: chunks
        .filter((c) => c.fileId === f.id)
        .map((c) => ({ index: c.index, sha256: c.sha256 })),
    })),
  };
}

export async function completeDrop(
  ctx: AppContext,
  drop: Drop,
  req: Req,
): Promise<{ status: 'READY' }> {
  if (drop.status === 'READY') return { status: 'READY' };
  if (drop.status !== 'UPLOADING') throw conflict('This drop is no longer accepting uploads');

  const [files, chunks] = await Promise.all([
    ctx.prisma.dropFile.findMany({ where: { dropId: drop.id } }),
    ctx.prisma.dropChunk.findMany({
      where: { dropId: drop.id },
      select: { fileId: true, index: true, size: true },
    }),
  ]);
  const missing: CompleteConflictDetails['missing'] = [];
  const sizeMismatch: NonNullable<CompleteConflictDetails['sizeMismatch']> = [];
  for (const f of files) {
    const mine = chunks.filter((c) => c.fileId === f.id && c.index < f.chunkCount);
    const have = new Set(mine.map((c) => c.index));
    const indexes: number[] = [];
    for (let i = 0; i < f.chunkCount; i++) if (!have.has(i)) indexes.push(i);
    if (indexes.length > 0) {
      missing.push({ fileId: f.id, indexes });
      continue;
    }
    const received = mine.reduce((s, c) => s + c.size, 0);
    if (BigInt(received) !== f.ciphertextBytes) {
      sizeMismatch.push({
        fileId: f.id,
        expectedBytes: Number(f.ciphertextBytes),
        receivedBytes: received,
      });
    }
  }
  if (missing.length > 0 || sizeMismatch.length > 0) {
    throw conflict('The upload is incomplete', {
      missing,
      ...(sizeMismatch.length > 0 ? { sizeMismatch } : {}),
    } satisfies CompleteConflictDetails);
  }

  const now = ctx.now();
  const completed = await ctx.prisma.$transaction(async (tx) => {
    const { count } = await tx.drop.updateMany({
      where: { id: drop.id, status: 'UPLOADING' },
      data: { status: 'READY', readyAt: now },
    });
    if (count !== 1) return false;
    if (drop.ownerId) {
      await tx.user.update({
        where: { id: drop.ownerId },
        data: { storageUsedBytes: { increment: drop.totalCiphertextBytes } },
      });
    }
    return true;
  });
  if (!completed) {
    const current = await ctx.prisma.drop.findUnique({
      where: { id: drop.id },
      select: { status: true },
    });
    if (current?.status === 'READY') return { status: 'READY' };
    throw conflict('This drop is no longer accepting uploads');
  }
  metrics.storageBytes.inc(Number(drop.totalCiphertextBytes));
  await ctx.audit.record({
    userId: drop.ownerId,
    dropId: drop.id,
    action: 'DROP_COMPLETED',
    req,
  });
  return { status: 'READY' };
}

/* ---------------------------------------------------------------- recipients */

/** A drop recipients may see: 404 when unknown or still uploading, 410 with the reason when gone. */
export async function availableDrop(ctx: AppContext, dropId: string): Promise<Drop> {
  const drop = await ctx.prisma.drop.findUnique({ where: { id: dropId } });
  if (!drop || drop.status === 'UPLOADING') throw notFound('Unknown drop');
  const reason = goneReason(drop, ctx.now());
  if (reason) throw gone(reason);
  return drop;
}

export function toDropMeta(drop: Drop): DropMeta {
  const kdf =
    drop.passwordProtected &&
    drop.pwKdfSalt &&
    drop.pwKdfMemoryKiB !== null &&
    drop.pwKdfIterations !== null &&
    drop.pwKdfParallelism !== null
      ? {
          salt: drop.pwKdfSalt,
          memoryKiB: drop.pwKdfMemoryKiB,
          iterations: drop.pwKdfIterations,
          parallelism: drop.pwKdfParallelism,
        }
      : null;
  return {
    id: drop.id,
    status: drop.status,
    fileCount: drop.fileCount,
    totalBytes: Number(drop.totalCiphertextBytes),
    expiresAt: drop.expiresAt.toISOString(),
    maxDownloads: drop.maxDownloads,
    downloadsRemaining: downloadsRemaining(drop),
    passwordProtected: drop.passwordProtected,
    encryptedManifest: drop.passwordProtected ? null : drop.encryptedManifest,
    passwordKdf: kdf,
    createdAt: drop.createdAt.toISOString(),
  };
}

/** Constant-time check of a presented drop authKey against the stored b64url(SHA-256(authKey)). */
function authKeyMatches(drop: Drop, authKey: string): boolean {
  const bytes = decodeB64url(authKey, 32);
  if (!bytes) throw validationError('authKey must be base64url of 32 bytes');
  return timingSafeEqualStr(sha256B64url(bytes), drop.authKeyHash ?? '');
}

async function auditUnlockFailure(ctx: AppContext, drop: Drop, req: Req): Promise<void> {
  await ctx.audit.record({
    userId: drop.ownerId,
    dropId: drop.id,
    action: 'DROP_UNLOCK_FAILED',
    req,
  });
}

export async function unlockDrop(
  ctx: AppContext,
  dropId: string,
  authKey: string,
  req: Req,
): Promise<{ wrappedDropKey: string; encryptedManifest: string }> {
  const drop = await availableDrop(ctx, dropId);
  if (!drop.passwordProtected || !drop.wrappedDropKey) {
    throw validationError('This drop is not password-protected');
  }
  if (!authKeyMatches(drop, authKey)) {
    await auditUnlockFailure(ctx, drop, req);
    throw unauthorized('Wrong password');
  }
  return { wrappedDropKey: drop.wrappedDropKey, encryptedManifest: drop.encryptedManifest };
}

interface ConsumedRow {
  downloadCount: number;
  maxDownloads: number;
}

/** min(now + TTL, createdAt + 24 h) (R12). */
export function grantExpiry(ctx: Pick<AppContext, 'env'>, createdAt: Date, now: Date): Date {
  const sliding = now.getTime() + ctx.env.DOWNLOAD_GRANT_TTL_MIN * MIN_MS;
  const cap = createdAt.getTime() + LIMITS.GRANT_MAX_LIFETIME_HOURS * HOUR_MS;
  return new Date(Math.min(sliding, cap));
}

/** A UTC timestamp parameter for raw SQL on Prisma's `timestamp(3)` (UTC wall time) columns. */
const utc = (d: Date) => Prisma.sql`(${d.toISOString()}::timestamptz AT TIME ZONE 'UTC')`;

export async function openDrop(
  ctx: AppContext,
  dropId: string,
  authKey: string | undefined,
  req: Req,
): Promise<OpenResponse> {
  const drop = await availableDrop(ctx, dropId);
  if (drop.passwordProtected) {
    if (!authKey) throw unauthorized('This drop needs its password');
    if (!authKeyMatches(drop, authKey)) {
      await auditUnlockFailure(ctx, drop, req);
      throw unauthorized('Wrong password');
    }
  }

  const now = ctx.now();
  const downloadToken = randomToken();
  const expiresAt = grantExpiry(ctx, now, now);
  const prefix = ipPrefix(req.ip);

  // Spec section 9: ONE conditional UPDATE consumes a download; the same statement flips the status to
  // EXHAUSTED when it takes the last one. Concurrent opens serialise on the row lock and re-check the WHERE.
  const consumed = await ctx.prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<ConsumedRow[]>`
      UPDATE "Drop"
      SET "downloadCount" = "downloadCount" + 1,
          "lastOpenedAt" = ${utc(now)},
          "status" = CASE WHEN "downloadCount" + 1 >= "maxDownloads"
                          THEN 'EXHAUSTED'::"DropStatus" ELSE "status" END
      WHERE "id" = ${dropId}
        AND "status" = 'READY'::"DropStatus"
        AND "expiresAt" > ${utc(now)}
        AND "downloadCount" < "maxDownloads"
      RETURNING "downloadCount", "maxDownloads"`;
    const row = rows[0];
    if (!row) return null;
    await tx.downloadGrant.create({
      data: {
        dropId,
        tokenHash: sha256B64url(downloadToken),
        isAdmin: false,
        ipPrefix: prefix,
        createdAt: now,
        expiresAt,
      },
    });
    return row;
  });

  if (!consumed) {
    // Lost the race (or the drop changed since availableDrop): answer with the current reason.
    const current = await ctx.prisma.drop.findUnique({ where: { id: dropId } });
    if (!current) throw notFound('Unknown drop');
    if (current.downloadCount >= current.maxDownloads) throw gone('EXHAUSTED');
    throw gone(goneReason(current, now) ?? 'EXHAUSTED');
  }

  metrics.dropOpens.inc();
  await ctx.audit.record({ userId: drop.ownerId, dropId, action: 'DROP_OPENED', req });
  return {
    downloadToken,
    expiresAt: expiresAt.toISOString(),
    downloadsRemaining: downloadsRemaining(consumed),
  };
}

/**
 * Resolve a download token for chunk GETs: the grant must exist, belong to this drop and be unexpired (401
 * otherwise); the drop must still have its blobs and be READY or EXHAUSTED (410 otherwise).
 */
export async function grantForDownload(
  ctx: AppContext,
  dropId: string,
  token: string | null,
): Promise<{ grantId: string; createdAt: Date }> {
  if (!token) throw unauthorized();
  const now = ctx.now();
  const grant = await ctx.prisma.downloadGrant.findUnique({
    where: { tokenHash: sha256B64url(token) },
    include: {
      drop: { select: { status: true, expiresAt: true, blobsDeletedAt: true } },
    },
  });
  if (!grant || grant.dropId !== dropId || grant.expiresAt.getTime() <= now.getTime()) {
    throw unauthorized('The download window has expired or the token is invalid');
  }
  const { status, blobsDeletedAt } = grant.drop;
  if (status === 'DELETED' || status === 'DISABLED' || status === 'EXPIRED') throw gone(status);
  if (blobsDeletedAt || (status !== 'READY' && status !== 'EXHAUSTED')) {
    throw gone(status === 'EXHAUSTED' ? 'EXHAUSTED' : 'EXPIRED');
  }
  return { grantId: grant.id, createdAt: grant.createdAt };
}

/* ---------------------------------------------------------------- owner */

export async function deleteDrop(
  ctx: AppContext,
  dropId: string,
  ownerToken: string | undefined,
  user: AuthUser | undefined,
  req: Req,
): Promise<void> {
  const drop = await ctx.prisma.drop.findUnique({ where: { id: dropId } });
  if (!drop) throw notFound('Unknown drop');
  const tokenOk =
    typeof ownerToken === 'string' &&
    timingSafeEqualStr(drop.ownerTokenHash, sha256B64url(ownerToken));
  const sessionOk = Boolean(user && drop.ownerId && user.id === drop.ownerId);
  if (!tokenOk && !sessionOk) {
    if (ownerToken === undefined && !user) throw unauthorized();
    throw forbidden('Only the owner can delete this drop');
  }

  const now = ctx.now();
  if (drop.status !== 'DELETED') {
    await ctx.prisma.drop.updateMany({
      where: { id: dropId, status: { not: 'DELETED' } },
      data: { status: 'DELETED', deletedAt: now },
    });
    await ctx.audit.record({ userId: drop.ownerId, dropId, action: 'DROP_DELETED', req });
  }
  await purgeDropBlobs(ctx, dropId, now);
}

export async function reportDrop(
  ctx: AppContext,
  dropId: string,
  body: { reason: Prisma.ReportCreateInput['reason']; details?: string; decryptionKey?: string },
  req: Req,
): Promise<{ id: string }> {
  const drop = await ctx.prisma.drop.findUnique({
    where: { id: dropId },
    select: { id: true, status: true, ownerId: true },
  });
  if (!drop || drop.status === 'UPLOADING') throw notFound('Unknown drop');
  const report = await ctx.prisma.report.create({
    data: {
      dropId,
      reason: body.reason,
      details: body.details ? body.details : null,
      providedKey: body.decryptionKey ?? null,
      reporterIpPrefix: ipPrefix(req.ip),
      createdAt: ctx.now(),
    },
    select: { id: true },
  });
  if (drop.ownerId) {
    // No `req`: the owner must not learn the reporter's IP prefix.
    await ctx.audit.record({ userId: drop.ownerId, dropId, action: 'DROP_REPORTED' });
  }
  return { id: report.id };
}
