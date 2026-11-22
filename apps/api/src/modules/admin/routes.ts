/**
 * /api/admin routes (spec section 10 "Admin", R13; audit log server-4, suspension and takedown server-6). Every route is auth 'admin' (requireAuth + requireRole
 * with a DB re-check). Logic lives in service.ts.
 */
import {
  AdminAuditPageSchema,
  AdminAuditQuerySchema,
  AdminDropDisableRequestSchema,
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
import {
  clearUserLock,
  disableDrop,
  getStats,
  hasAdminStepUp,
  listAudit,
  listReports,
  listUsers,
  patchUser,
  resolveReport,
  reviewGrant,
} from './service';

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
      summary:
        'Abuse reports (decryptionKey is exposed only here, and only within ADMIN_STEP_UP_MINUTES of a sign-in or step-up)',
      tags,
      auth,
      request: { query: AdminReportsQuerySchema },
      responses: { 200: { description: 'Page of reports', schema: AdminReportPageSchema } },
    },
    async (req, res) => {
      const withKeys = await hasAdminStepUp(ctx, authUser(req));
      res.json(await listReports(ctx, req.validatedQuery, { withKeys }));
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
      await resolveReport(ctx, req.validatedParams.id, req.body.action, authUser(req), req);
      res.status(204).end();
    },
  );
  r.route(
    {
      method: 'post',
      path: '/drops/:id/grant',
      summary: 'Non-consuming review grant (audited; needs a recent sign-in or step-up)',
      tags,
      auth,
      request: { params: DropIdParamsSchema },
      responses: {
        200: { description: 'Review grant', schema: AdminGrantResponseSchema },
        403: { description: 'No recent step-up (FORBIDDEN; details.reason STEP_UP_REQUIRED)' },
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
      summary:
        'Edit a user role and/or storage quota (only accounts with 2FA can become admins; a promotion needs a recent sign-in or step-up)',
      tags,
      auth,
      request: { params: UserIdParamsSchema, body: AdminUserPatchRequestSchema },
      responses: {
        200: { description: 'Updated user', schema: AdminUserResponseSchema },
        403: {
          description:
            'Promotion without a recent step-up (FORBIDDEN; details.reason STEP_UP_REQUIRED)',
        },
        404: { description: 'Unknown user' },
        409: { description: 'Promotion of an account without two-step verification (CONFLICT)' },
      },
    },
    async (req, res) => {
      res.json({
        user: await patchUser(ctx, req.validatedParams.id, req.body, authUser(req), req),
      });
    },
  );
  r.route(
    {
      method: 'post',
      path: '/drops/:id/disable',
      summary: 'Take a drop down without a report (blobs deleted, open reports resolved, audited)',
      tags,
      auth,
      request: { params: DropIdParamsSchema, body: AdminDropDisableRequestSchema },
      responses: {
        204: { description: 'Disabled' },
        404: { description: 'Unknown drop' },
        409: { description: 'Already disabled or deleted (CONFLICT)' },
      },
    },
    async (req, res) => {
      await disableDrop(ctx, req.validatedParams.id, authUser(req), {
        reason: req.body.reason,
        req,
        requireChange: true,
      });
      res.status(204).end();
    },
  );
  r.route(
    {
      method: 'get',
      path: '/audit',
      summary: 'Instance audit log, newest first (admin and operator actions by default)',
      tags,
      auth,
      request: { query: AdminAuditQuerySchema },
      responses: { 200: { description: 'Page of audit events', schema: AdminAuditPageSchema } },
    },
    async (req, res) => {
      res.json(await listAudit(ctx, req.validatedQuery));
    },
  );
  r.route(
    {
      method: 'post',
      path: '/users/:id/clear-lock',
      summary: 'Clear the sign-in lockout of an account (audited on the account and on the admin)',
      tags,
      auth,
      request: { params: UserIdParamsSchema },
      responses: {
        200: { description: 'Updated user', schema: AdminUserResponseSchema },
        404: { description: 'Unknown user' },
      },
    },
    async (req, res) => {
      res.json({
        user: await clearUserLock(ctx, req.validatedParams.id, authUser(req), req),
      });
    },
  );

  return r;
}
