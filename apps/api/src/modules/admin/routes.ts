/**
 * /api/admin routes (spec section 10 "Admin", R13). Every route is auth 'admin' (requireAuth + requireRole
 * with a DB re-check). Logic lives in service.ts.
 */
import {
  AdminGrantResponseSchema,
  AdminReportPageSchema,
  AdminReportsQuerySchema,
  AdminResolveRequestSchema,
  AdminStatsSchema,
  AdminUserPageSchema,
  AdminUserPatchRequestSchema,
  AdminUserResponseSchema,
  AdminUsersQuerySchema,
  DropIdParamsSchema,
  ReportIdParamsSchema,
  UserIdParamsSchema,
} from '@cipherdrop/shared';
import type { AppContext } from '../../context';
import { authUser } from '../../middleware/auth';
import { createRouter, type AppRouter } from '../../lib/router';
import { getStats, listReports, listUsers, patchUser, resolveReport, reviewGrant } from './service';

export function adminRoutes(ctx: AppContext): AppRouter {
  const r = createRouter('/api/admin');
  const tags = ['admin'];
  const auth = 'admin' as const;

  r.route(
    {
      method: 'get',
      path: '/stats',
      summary: 'Totals and uploads over the last 14 days',
      tags,
      auth,
      responses: { 200: { description: 'Stats', schema: AdminStatsSchema } },
    },
    async (_req, res) => {
      res.json(await getStats(ctx));
    },
  );
  r.route(
    {
      method: 'get',
      path: '/reports',
      summary: 'Abuse reports (decryptionKey is exposed only here)',
      tags,
      auth,
      request: { query: AdminReportsQuerySchema },
      responses: { 200: { description: 'Page of reports', schema: AdminReportPageSchema } },
    },
    async (req, res) => {
      res.json(await listReports(ctx, req.validatedQuery));
    },
  );
  r.route(
    {
      method: 'post',
      path: '/reports/:id/resolve',
      summary: 'Resolve a report: disable the drop (blobs deleted) or dismiss',
      tags,
      auth,
      request: { params: ReportIdParamsSchema, body: AdminResolveRequestSchema },
      responses: { 204: { description: 'Resolved' }, 404: { description: 'Unknown report' } },
    },
    async (req, res) => {
      await resolveReport(ctx, req.validatedParams.id, req.body.action, authUser(req));
      res.status(204).end();
    },
  );
  r.route(
    {
      method: 'post',
      path: '/drops/:id/grant',
      summary: 'Non-consuming review grant (audited)',
      tags,
      auth,
      request: { params: DropIdParamsSchema },
      responses: {
        200: { description: 'Review grant', schema: AdminGrantResponseSchema },
        404: { description: 'Unknown drop' },
      },
    },
    async (req, res) => {
      res.json(await reviewGrant(ctx, req.validatedParams.id, authUser(req), req));
    },
  );
  r.route(
    {
      method: 'get',
      path: '/users',
      summary: 'Users (search by email)',
      tags,
      auth,
      request: { query: AdminUsersQuerySchema },
      responses: { 200: { description: 'Page of users', schema: AdminUserPageSchema } },
    },
    async (req, res) => {
      res.json(await listUsers(ctx, req.validatedQuery));
    },
  );
  r.route(
    {
      method: 'patch',
      path: '/users/:id',
      summary: 'Edit a user role and/or storage quota',
      tags,
      auth,
      request: { params: UserIdParamsSchema, body: AdminUserPatchRequestSchema },
      responses: {
        200: { description: 'Updated user', schema: AdminUserResponseSchema },
        404: { description: 'Unknown user' },
      },
    },
    async (req, res) => {
      res.json({ user: await patchUser(ctx, req.validatedParams.id, req.body, authUser(req)) });
    },
  );

  return r;
}
