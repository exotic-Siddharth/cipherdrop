/**
 * Health endpoints (spec section 10): /healthz (liveness), /readyz (DB + Redis + storage), /metrics (Prometheus).
 * Mounted at the root (not under /api).
 */
import { z } from 'zod';
import type { AppContext } from '../../context';
import { metricsRegistry } from '../../lib/metrics';
import { createRouter, type AppRouter } from '../../lib/router';

const HealthSchema = z.object({ ok: z.literal(true) });
const ReadySchema = z.object({
  ok: z.boolean(),
  checks: z.object({
    db: z.enum(['ok', 'error']),
    redis: z.enum(['ok', 'error']),
    storage: z.enum(['ok', 'error']),
  }),
});

const CHECK_TIMEOUT_MS = 3000;

async function check(fn: () => Promise<unknown>): Promise<'ok' | 'error'> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      fn(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), CHECK_TIMEOUT_MS);
      }),
    ]);
    return 'ok';
  } catch {
    return 'error';
  } finally {
    clearTimeout(timer);
  }
}

export function healthRoutes(ctx: AppContext): AppRouter {
  const r = createRouter('');
  const tags = ['health'];

  r.route(
    {
      method: 'get',
      path: '/healthz',
      summary: 'Liveness',
      tags,
      responses: { 200: { description: 'Alive', schema: HealthSchema } },
    },
    (_req, res) => {
      res.json({ ok: true });
    },
  );

  r.route(
    {
      method: 'get',
      path: '/readyz',
      summary: 'Readiness: database, Redis and blob storage',
      tags,
      responses: {
        200: { description: 'Ready', schema: ReadySchema },
        503: { description: 'Not ready', schema: ReadySchema },
      },
    },
    async (_req, res) => {
      const [db, redis, storage] = await Promise.all([
        check(() => ctx.prisma.$queryRaw`SELECT 1`),
        check(() => ctx.redis.ping()),
        check(() => ctx.storage.healthCheck()),
      ]);
      const ok = db === 'ok' && redis === 'ok' && storage === 'ok';
      res.status(ok ? 200 : 503).json({ ok, checks: { db, redis, storage } });
    },
  );

  r.route(
    {
      method: 'get',
      path: '/metrics',
      summary: 'Prometheus metrics',
      tags,
      responses: { 200: { description: 'Prometheus text format', contentType: 'text/plain' } },
    },
    async (_req, res) => {
      res.setHeader('Content-Type', metricsRegistry.contentType);
      res.send(await metricsRegistry.metrics());
    },
  );

  return r;
}
