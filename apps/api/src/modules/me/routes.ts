/**
 * /api/me routes (spec section 10, R6): the signed-in user, settings, activity log, owned drops and account
 * deletion. Owned-drop summaries carry only ciphertext (encrypted manifest, owner-wrapped key): the dashboard
 * decrypts names locally with the vault.
 */
import {
  AuditEventPageSchema,
  DeleteMeRequestSchema,
  MeAuditQuerySchema,
  MeDropsQuerySchema,
  MeResponseSchema,
  MeSettingsRequestSchema,
  OwnerDropPageSchema,
  type AuditEventDto,
  type DropStatus,
  type MeDropsStatus,
  type OwnerDropSummary,
} from '@cipherdrop/shared';
import type { AppContext } from '../../context';
import { paginate, toPage } from '../../lib/pagination';
import { createRouter, type AppRouter } from '../../lib/router';
import { authUser } from '../../middleware/auth';
import {
  clearRefreshCookie,
  loadUser,
  requireAccountProof,
  revokeUserSessions,
  toMe,
} from '../auth/service';

/** R6: active = UPLOADING|READY; expired = EXPIRED|EXHAUSTED|DISABLED; all = everything except DELETED. */
const STATUS_FILTER: Record<MeDropsStatus, DropStatus[]> = {
  active: ['UPLOADING', 'READY'],
  expired: ['EXPIRED', 'EXHAUSTED', 'DISABLED'],
  all: ['UPLOADING', 'READY', 'EXHAUSTED', 'EXPIRED', 'DISABLED'],
};

export function meRoutes(ctx: AppContext): AppRouter {
  const r = createRouter('/api/me');
  const tags = ['me'];
  const { prisma } = ctx;
  const reauthLimit = ctx.rateLimit({
    name: 'reauth',
    windowMs: 15 * 60_000,
    limit: 10,
    key: (req) => `user|${req.user?.id ?? 'anonymous'}`,
  });

  r.route(
    {
      method: 'get',
      path: '/',
      summary: 'The signed-in user, with storage numbers',
      tags,
      auth: 'user',
      responses: { 200: { description: 'Current user', schema: MeResponseSchema } },
    },
    async (req, res) => {
      res.json({ user: toMe(await loadUser(ctx, authUser(req).id)) });
    },
  );

  r.route(
    {
      method: 'patch',
      path: '/settings',
      summary: 'Update settings (vault auto-lock: 5, 15 or 60 minutes)',
      tags,
      auth: 'user',
      request: { body: MeSettingsRequestSchema },
      responses: { 200: { description: 'Updated user', schema: MeResponseSchema } },
    },
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      const updated = await prisma.user.update({
        where: { id: user.id },
        data: { autoLockMinutes: req.body.autoLockMinutes },
      });
      res.json({ user: toMe(updated) });
    },
  );

  r.route(
    {
      method: 'delete',
      path: '/',
      summary: 'Delete the account, its drops and their blobs',
      tags,
      auth: 'user',
      request: { body: DeleteMeRequestSchema },
      responses: {
        204: { description: 'Account deleted' },
        403: { description: 'Wrong authKey or two-factor code (FORBIDDEN)' },
      },
    },
    reauthLimit,
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      await requireAccountProof(ctx, user, req.body, req, 'account-deletion');

      // Stop serving the drops first (a chunk PUT in flight finishes before this update gets the row lock, and
      // later ones see DELETED), then list them, so a drop created meanwhile is purged too, and delete their
      // blobs. A storage failure aborts here (500) with the account intact and the session alive, so the user
      // can simply retry (deleteDrop is idempotent).
      await prisma.drop.updateMany({
        where: { ownerId: user.id, status: { not: 'DELETED' } },
        data: { status: 'DELETED', deletedAt: ctx.now() },
      });
      const drops = await prisma.drop.findMany({
        where: { ownerId: user.id },
        select: { id: true },
      });
      for (const drop of drops) await ctx.storage.deleteDrop(drop.id);

      // Sessions die at once (denylist), then the user row goes with everything that cascades from it.
      await revokeUserSessions(ctx, user.id);
      await prisma.user.delete({ where: { id: user.id } });
      await ctx.audit.record({
        userId: null,
        action: 'ACCOUNT_DELETED',
        req,
        metadata: { drops: drops.length },
      });
      clearRefreshCookie(ctx, res);
      res.status(204).end();
    },
  );

  r.route(
    {
      method: 'get',
      path: '/audit',
      summary: 'Activity log (newest first), filterable by action',
      tags,
      auth: 'user',
      request: { query: MeAuditQuerySchema },
      responses: { 200: { description: 'Page of audit events', schema: AuditEventPageSchema } },
    },
    async (req, res) => {
      const { action, ...pageQuery } = req.validatedQuery;
      const p = paginate(pageQuery);
      const page = await ctx.audit.list(authUser(req).id, {
        action,
        page: p.page,
        pageSize: p.pageSize,
      });
      const items: AuditEventDto[] = page.items.map((e) => ({
        id: e.id,
        action: e.action,
        dropId: e.dropId,
        ipPrefix: e.ipPrefix,
        userAgent: e.userAgent,
        metadata:
          e.metadata && typeof e.metadata === 'object' && !Array.isArray(e.metadata)
            ? (e.metadata as Record<string, unknown>)
            : null,
        createdAt: e.createdAt.toISOString(),
      }));
      res.json(toPage(items, page.total, p));
    },
  );

  r.route(
    {
      method: 'get',
      path: '/drops',
      summary: 'Owned drops (status=active|expired|all, newest first)',
      tags,
      auth: 'user',
      request: { query: MeDropsQuerySchema },
      responses: { 200: { description: 'Page of owned drops', schema: OwnerDropPageSchema } },
    },
    async (req, res) => {
      const { status, ...pageQuery } = req.validatedQuery;
      const p = paginate(pageQuery);
      const where = { ownerId: authUser(req).id, status: { in: STATUS_FILTER[status] } };
      const [total, drops] = await prisma.$transaction([
        prisma.drop.count({ where }),
        prisma.drop.findMany({
          where,
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          skip: p.skip,
          take: p.take,
          select: {
            id: true,
            status: true,
            fileCount: true,
            totalCiphertextBytes: true,
            maxDownloads: true,
            downloadCount: true,
            expiresAt: true,
            createdAt: true,
            lastOpenedAt: true,
            passwordProtected: true,
            encryptedManifest: true,
            ownerWrappedKey: true,
          },
        }),
      ]);
      const items: OwnerDropSummary[] = drops.map((d) => ({
        id: d.id,
        status: d.status,
        fileCount: d.fileCount,
        totalBytes: Number(d.totalCiphertextBytes),
        maxDownloads: d.maxDownloads,
        downloadCount: d.downloadCount,
        downloadsRemaining: Math.max(0, d.maxDownloads - d.downloadCount),
        expiresAt: d.expiresAt.toISOString(),
        createdAt: d.createdAt.toISOString(),
        lastOpenedAt: d.lastOpenedAt ? d.lastOpenedAt.toISOString() : null,
        passwordProtected: d.passwordProtected,
        encryptedManifest: d.encryptedManifest,
        ownerWrappedKey: d.ownerWrappedKey,
      }));
      res.json(toPage(items, total, p));
    },
  );

  return r;
}
