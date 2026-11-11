/**
 * /api/drops routes (spec sections 9 and 10 "Drops", R5, R7, R10, R11, R12). Business logic lives in
 * service.ts; this file wires validation, limiters and token checks.
 *
 * Chunk PUT: the upload token, the drop status, the file, the index, X-Chunk-SHA256 and the declared
 * Content-Length are checked BEFORE the body is read; then express.raw({ type: 'application/octet-stream',
 * limit: LIMITS.MAX_CHUNK_BYTES }) buffers it, the exact size and the SHA-256 are verified, and only then is
 * the chunk written (atomically) and recorded. The chunk routes are exempt from the global limiter and use
 * the per-token chunkPut / chunkGet limiters keyed on sha256B64url(token) (R10).
 */
import { pipeline } from 'node:stream/promises';
import {
  ChunkParamsSchema,
  ChunkUploadHeadersSchema,
  CompleteDropResponseSchema,
  CreateDropRequestSchema,
  CreateDropResponseSchema,
  DropIdParamsSchema,
  DropMetaSchema,
  LIMITS,
  OpenRequestSchema,
  OpenResponseSchema,
  OWNER_TOKEN_HEADER,
  OwnerTokenHeadersSchema,
  ReportRequestSchema,
  ReportResponseSchema,
  SHA256_HEX_RE,
  UnlockRequestSchema,
  UnlockResponseSchema,
  UploadStatusSchema,
  CHUNK_SHA256_HEADER,
} from '@cipherdrop/shared';
import express, { type Request, type RequestHandler, type Response } from 'express';
import type { AppContext } from '../../context';
import { conflict, notFound, payloadTooLarge, validationError } from '../../lib/errors';
import { sha256B64url, sha256Hex, timingSafeEqualStr } from '../../lib/hash';
import { ipKey } from '../../lib/ip';
import { metrics } from '../../lib/metrics';
import { createRouter, type AppRouter } from '../../lib/router';
import { bearerToken } from '../../lib/tokens';
import {
  availableDrop,
  completeDrop,
  createDrop,
  deleteDrop,
  dropForUploadToken,
  expectedChunkSize,
  grantExpiry,
  grantForDownload,
  openDrop,
  reportDrop,
  toDropMeta,
  unlockDrop,
  uploadStatus,
} from './service';

interface PendingChunk {
  expected: number;
  sha: string;
}

/** Rate-limit bucket for a capability token: never the raw token (R10). */
const tokenKey = (req: Request) => sha256B64url(bearerToken(req) ?? '');
const paramId = (req: Request) => String(req.params.id ?? '');

/** Rejected chunk bodies up to this size are read and discarded, larger ones close the connection. */
const DISCARD_LIMIT = LIMITS.MAX_CHUNK_BYTES + 64 * 1024;

/**
 * Read and discard the body of a chunk PUT rejected before its body was read, so the client receives the
 * 4xx instead of a connection reset (browsers report a reset mid-upload as a network error). Bounded by
 * DISCARD_LIMIT; bodies without a Content-Length or above it get Connection: close instead.
 */
async function discardBody(req: Request, res: Response): Promise<void> {
  if (req.complete || req.readableEnded) return;
  const declared = Number(req.headers['content-length']);
  if (!Number.isFinite(declared) || declared > DISCARD_LIMIT) {
    res.setHeader('Connection', 'close');
    return;
  }
  await new Promise<void>((resolve) => {
    req.once('end', resolve);
    req.once('error', () => resolve());
    req.once('close', () => resolve());
    req.resume();
  });
}

export function dropsRoutes(ctx: AppContext): AppRouter {
  const r = createRouter('/api/drops');
  const tags = ['drops'];

  // Limiters are built once per app (each owns a RedisStore).
  const createAnonLimiter = ctx.rateLimit({ name: 'createDropAnon', key: (req) => ipKey(req.ip) });
  const createUserLimiter = ctx.rateLimit({
    name: 'createDropUser',
    key: (req) => req.user?.id ?? 'anonymous',
  });
  const createLimiter: RequestHandler = (req, res, next) =>
    (req.user ? createUserLimiter : createAnonLimiter)(req, res, next);
  const chunkPutLimiter = ctx.rateLimit({ name: 'chunkPut', key: tokenKey });
  const chunkGetLimiter = ctx.rateLimit({ name: 'chunkGet', key: tokenKey });
  const openLimiter = ctx.rateLimit({ name: 'open', key: (req) => ipKey(req.ip) });
  const unlockIpLimiter = ctx.rateLimit({
    name: 'unlockDropIp',
    key: (req) => `${paramId(req)}|${ipKey(req.ip)}`,
  });
  const unlockDropLimiter = ctx.rateLimit({ name: 'unlockDrop', key: paramId });
  const reportLimiter = ctx.rateLimit({ name: 'report', key: (req) => ipKey(req.ip) });
  const rawChunk = express.raw({
    type: 'application/octet-stream',
    limit: LIMITS.MAX_CHUNK_BYTES,
  });
  const gone = { description: 'Expired, exhausted, deleted or disabled (GONE, details.reason)' };

  r.route(
    {
      method: 'post',
      path: '/',
      summary: 'Create a drop (anonymous or signed in); returns the owner and upload tokens',
      tags,
      auth: 'optional',
      request: { body: CreateDropRequestSchema },
      responses: {
        201: { description: 'Drop created (UPLOADING)', schema: CreateDropResponseSchema },
        413: {
          description:
            'Per-drop byte limit or storage quota exceeded (PAYLOAD_TOO_LARGE / QUOTA_EXCEEDED)',
        },
      },
    },
    createLimiter,
    async (req, res) => {
      res.status(201).json(await createDrop(ctx, req.body, req.user, req));
    },
  );
  r.route(
    {
      method: 'put',
      path: '/:id/files/:fileId/chunks/:index',
      summary:
        'Upload one ciphertext chunk (X-Chunk-SHA256 = lowercase hex of the body; re-PUT overwrites)',
      tags,
      auth: 'uploadToken',
      request: {
        params: ChunkParamsSchema,
        headers: ChunkUploadHeadersSchema,
        rawBody: {
          contentType: 'application/octet-stream',
          description:
            'Ciphertext chunk: exactly CHUNK_SIZE+16 bytes, or 16..CHUNK_SIZE+16 for the final chunk',
        },
      },
      responses: {
        204: { description: 'Stored' },
        409: { description: 'The drop is no longer accepting uploads (CONFLICT)' },
        413: { description: 'Chunk larger than CHUNK_SIZE+16 (PAYLOAD_TOO_LARGE)' },
      },
    },
    chunkPutLimiter,
    // 1. Everything that does not need the body, before reading it.
    async (req, res, next) => {
      let authenticated = false;
      try {
        const { id, fileId, index } = req.validatedParams;
        const drop = await dropForUploadToken(ctx, id, bearerToken(req));
        authenticated = true;
        if (drop.status !== 'UPLOADING') throw conflict('This drop is no longer accepting uploads');
        const file = await ctx.prisma.dropFile.findUnique({
          where: { dropId_id: { dropId: id, id: fileId } },
        });
        if (!file) throw notFound('Unknown file');
        if (index >= file.chunkCount) throw validationError('Chunk index out of range');
        const sha = req.headers[CHUNK_SHA256_HEADER];
        if (typeof sha !== 'string' || !SHA256_HEX_RE.test(sha)) {
          throw validationError('X-Chunk-SHA256 must be the lowercase hex SHA-256 of the body');
        }
        if (!req.is('application/octet-stream')) {
          throw validationError('The chunk body must be application/octet-stream');
        }
        const expected = expectedChunkSize(file, index);
        const declared = req.headers['content-length'];
        if (declared !== undefined) {
          const n = Number(declared);
          if (n > LIMITS.MAX_CHUNK_BYTES) throw payloadTooLarge('Chunk larger than allowed');
          if (n !== expected) {
            throw validationError('Wrong chunk size', { expectedBytes: expected });
          }
        }
        res.locals.pendingChunk = { expected, sha } satisfies PendingChunk;
      } catch (err) {
        // Only a verified uploader gets its rejected body read; anyone else gets the connection closed.
        if (authenticated) await discardBody(req, res);
        else res.setHeader('Connection', 'close');
        throw err;
      }
      next();
    },
    // 2. Buffer the body (at most CHUNK_SIZE + 16 bytes).
    rawChunk,
    // 3. Verify it, then write it atomically and record it.
    async (req, res) => {
      const { id, fileId, index } = req.validatedParams;
      const { expected, sha } = res.locals.pendingChunk as PendingChunk;
      const body: unknown = req.body;
      if (!Buffer.isBuffer(body)) throw validationError('Missing chunk body');
      if (body.length !== expected) {
        throw validationError('Wrong chunk size', { expectedBytes: expected });
      }
      if (!timingSafeEqualStr(sha256Hex(body), sha)) {
        throw validationError('X-Chunk-SHA256 does not match the body');
      }
      await ctx.storage.putChunk(id, fileId, index, body);
      await ctx.prisma.dropChunk.upsert({
        where: { dropId_fileId_index: { dropId: id, fileId, index } },
        create: { dropId: id, fileId, index, size: body.length, sha256: sha },
        update: { size: body.length, sha256: sha },
      });
      metrics.chunkBytesUploaded.inc(body.length);
      res.status(204).end();
    },
  );
  r.route(
    {
      method: 'get',
      path: '/:id/upload-status',
      summary: 'Received chunks with their SHA-256 (resume after reload, R11)',
      tags,
      auth: 'uploadToken',
      request: { params: DropIdParamsSchema },
      responses: { 200: { description: 'Upload status', schema: UploadStatusSchema } },
    },
    async (req, res) => {
      const drop = await dropForUploadToken(ctx, req.validatedParams.id, bearerToken(req));
      res.json(await uploadStatus(ctx, drop));
    },
  );
  r.route(
    {
      method: 'post',
      path: '/:id/complete',
      summary: 'Mark the drop READY once every chunk is present and sizes match',
      tags,
      auth: 'uploadToken',
      request: { params: DropIdParamsSchema },
      responses: {
        200: { description: 'READY', schema: CompleteDropResponseSchema },
        409: { description: 'Missing chunks or size mismatch (CONFLICT, details)' },
      },
    },
    async (req, res) => {
      const drop = await dropForUploadToken(ctx, req.validatedParams.id, bearerToken(req));
      res.json(await completeDrop(ctx, drop, req));
    },
  );
  r.route(
    {
      method: 'get',
      path: '/:id',
      summary: 'Drop metadata (encryptedManifest is null for password drops)',
      tags,
      request: { params: DropIdParamsSchema },
      responses: {
        200: { description: 'Drop metadata', schema: DropMetaSchema },
        404: { description: 'Unknown drop' },
        410: gone,
      },
    },
    async (req, res) => {
      res.json(toDropMeta(await availableDrop(ctx, req.validatedParams.id)));
    },
  );
  r.route(
    {
      method: 'post',
      path: '/:id/unlock',
      summary:
        'Release the wrapped drop key of a password drop (constant-time authKey check, rate limited)',
      tags,
      request: { params: DropIdParamsSchema, body: UnlockRequestSchema },
      responses: {
        200: {
          description: 'Wrapped drop key and encrypted manifest',
          schema: UnlockResponseSchema,
        },
        401: { description: 'Wrong password (audited to the owner)' },
        404: { description: 'Unknown drop' },
        410: gone,
      },
    },
    unlockIpLimiter,
    unlockDropLimiter,
    async (req, res) => {
      res.json(await unlockDrop(ctx, req.validatedParams.id, req.body.authKey, req));
    },
  );
  r.route(
    {
      method: 'post',
      path: '/:id/open',
      summary: 'Consume one download atomically and issue a download grant',
      tags,
      request: { params: DropIdParamsSchema, body: OpenRequestSchema },
      responses: {
        200: { description: 'Download grant', schema: OpenResponseSchema },
        401: { description: 'Password drop without a valid authKey' },
        404: { description: 'Unknown drop' },
        410: gone,
      },
    },
    openLimiter,
    async (req, res) => {
      res.json(await openDrop(ctx, req.validatedParams.id, req.body.authKey, req));
    },
  );
  r.route(
    {
      method: 'get',
      path: '/:id/files/:fileId/chunks/:index',
      summary: 'Stream one ciphertext chunk (valid grant required; slides the grant expiry)',
      tags,
      auth: 'downloadToken',
      request: { params: ChunkParamsSchema },
      responses: {
        200: { description: 'Ciphertext chunk', contentType: 'application/octet-stream' },
        404: { description: 'Unknown chunk' },
      },
    },
    chunkGetLimiter,
    async (req, res) => {
      const { id, fileId, index } = req.validatedParams;
      const grant = await grantForDownload(ctx, id, bearerToken(req));
      const chunk = await ctx.prisma.dropChunk.findUnique({
        where: { dropId_fileId_index: { dropId: id, fileId, index } },
        select: { size: true },
      });
      if (!chunk) throw notFound('Unknown chunk');
      // R12: every successful chunk GET slides the grant, capped at createdAt + 24 h.
      await ctx.prisma.downloadGrant.update({
        where: { id: grant.grantId },
        data: { expiresAt: grantExpiry(ctx, grant.createdAt, ctx.now()) },
      });
      const stream = await ctx.storage.getChunkStream(id, fileId, index);
      res.status(200);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', String(chunk.size));
      try {
        await pipeline(stream, res);
        metrics.chunkBytesDownloaded.inc(chunk.size);
      } catch (err) {
        stream.destroy();
        if (!res.headersSent) throw err;
        // Mid-stream failure or client abort: the length no longer matches, so drop the connection.
        res.destroy();
        ctx.logger.warn({ err: { code: (err as { code?: string }).code } }, 'chunk stream aborted');
      }
    },
  );
  r.route(
    {
      method: 'delete',
      path: '/:id',
      summary: 'Delete a drop and its blobs (X-Owner-Token or the owner session)',
      tags,
      auth: 'owner',
      request: { params: DropIdParamsSchema, headers: OwnerTokenHeadersSchema },
      responses: {
        204: { description: 'Deleted' },
        403: { description: 'Not the owner' },
        404: { description: 'Unknown drop' },
      },
    },
    async (req, res) => {
      const header = req.headers[OWNER_TOKEN_HEADER];
      const ownerToken = typeof header === 'string' ? header : undefined;
      await deleteDrop(ctx, req.validatedParams.id, ownerToken, req.user, req);
      res.status(204).end();
    },
  );
  r.route(
    {
      method: 'post',
      path: '/:id/report',
      summary: 'Report abuse (the decryption key only if the reporter opts in)',
      tags,
      request: { params: DropIdParamsSchema, body: ReportRequestSchema },
      responses: {
        201: { description: 'Report stored', schema: ReportResponseSchema },
        404: { description: 'Unknown drop' },
      },
    },
    reportLimiter,
    async (req, res) => {
      res.status(201).json(await reportDrop(ctx, req.validatedParams.id, req.body, req));
    },
  );

  return r;
}
