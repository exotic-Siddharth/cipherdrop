/**
 * GET /api/config (server-1, ops-3): the operator switches the SPA needs to explain a closed door up front
 * instead of after the user has picked files or derived keys. Public and static per process (env only): it
 * says what this instance allows, never how full it is.
 */
import { PublicConfigSchema, type PublicConfig } from '@cipherdrop/shared';
import type { AppContext } from '../../context';
import { createRouter, type AppRouter } from '../../lib/router';

export function publicConfig(ctx: Pick<AppContext, 'env'>): PublicConfig {
  return {
    anonymousUploads: ctx.env.ALLOW_ANONYMOUS_UPLOADS,
    registration: ctx.env.ALLOW_REGISTRATION,
  };
}

export function configRoutes(ctx: AppContext): AppRouter {
  const r = createRouter('/api/config');
  r.route(
    {
      method: 'get',
      path: '/',
      summary: 'Operator switches the SPA needs: anonymous uploads and registration on or off',
      tags: ['config'],
      auth: 'public',
      responses: { 200: { description: 'Public configuration', schema: PublicConfigSchema } },
    },
    (_req, res) => {
      res.json(publicConfig(ctx));
    },
  );
  return r;
}
