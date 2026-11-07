/**
 * /api/me routes (spec section 10, R6). S4 STUB: every handler answers 501.
 * B1 owns this file: replace the handlers, keep the defs.
 */
import {
  AuditEventPageSchema,
  DeleteMeRequestSchema,
  MeAuditQuerySchema,
  MeDropsQuerySchema,
  MeResponseSchema,
  MeSettingsRequestSchema,
  OwnerDropPageSchema,
} from '@cipherdrop/shared';
import type { AppContext } from '../../context';
import { notImplemented } from '../../lib/errors';
import { createRouter, type AppRouter } from '../../lib/router';

export function meRoutes(_ctx: AppContext): AppRouter {
  const r = createRouter('/api/me');
  const tags = ['me'];
  const stub = () => {
    throw notImplemented();
  };

  r.route(
    {
      method: 'get',
      path: '/',
      summary: 'The signed-in user, with storage numbers',
      tags,
      auth: 'user',
      responses: { 200: { description: 'Current user', schema: MeResponseSchema } },
    },
    stub,
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
    stub,
  );
  r.route(
    {
      method: 'delete',
      path: '/',
      summary: 'Delete the account, its drops and their blobs',
      tags,
      auth: 'user',
      request: { body: DeleteMeRequestSchema },
      responses: { 204: { description: 'Account deleted' } },
    },
    stub,
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
    stub,
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
    stub,
  );

  return r;
}
