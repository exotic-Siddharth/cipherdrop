/**
 * /api/drops routes (spec sections 9 and 10 "Drops", R5, R11, R12). S4 STUB: every handler answers 501.
 * B2 owns this file: replace the handlers, keep the defs, add the limiters (ctx.rateLimit: createDropAnon /
 * createDropUser, chunkPut / chunkGet keyed on sha256B64url(token), open, unlockDropIp + unlockDrop, report).
 *
 * Chunk PUT: check the upload token BEFORE reading the body, then
 * express.raw({ type: 'application/octet-stream', limit: LIMITS.MAX_CHUNK_BYTES }). The chunk routes are
 * exempt from the global limiter (createApp skips them).
 */
import {
  ChunkParamsSchema,
  ChunkUploadHeadersSchema,
  CompleteDropResponseSchema,
  CreateDropRequestSchema,
  CreateDropResponseSchema,
  DropIdParamsSchema,
  DropMetaSchema,
  OpenRequestSchema,
  OpenResponseSchema,
  OwnerTokenHeadersSchema,
  ReportRequestSchema,
  ReportResponseSchema,
  UnlockRequestSchema,
  UnlockResponseSchema,
  UploadStatusSchema,
} from '@cipherdrop/shared';
import type { AppContext } from '../../context';
import { notImplemented } from '../../lib/errors';
import { createRouter, type AppRouter } from '../../lib/router';

export function dropsRoutes(_ctx: AppContext): AppRouter {
  const r = createRouter('/api/drops');
  const tags = ['drops'];
  const stub = () => {
    throw notImplemented();
  };
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
  );

  return r;
}
