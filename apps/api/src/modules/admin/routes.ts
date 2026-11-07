/**
 * /api/admin routes (spec section 10 "Admin", R13). Every route is auth 'admin' (requireAuth + requireRole
 * with a DB re-check). S4 STUB: every handler answers 501. B2 owns this file: replace the handlers, keep the defs.
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
import { notImplemented } from '../../lib/errors';
import { createRouter, type AppRouter } from '../../lib/router';

export function adminRoutes(_ctx: AppContext): AppRouter {
  const r = createRouter('/api/admin');
  const tags = ['admin'];
  const auth = 'admin' as const;
  const stub = () => {
    throw notImplemented();
  };

  r.route(
    {
      method: 'get',
      path: '/stats',
      summary: 'Totals and uploads over the last 14 days',
      tags,
      auth,
      responses: { 200: { description: 'Stats', schema: AdminStatsSchema } },
    },
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
  );

  return r;
}
