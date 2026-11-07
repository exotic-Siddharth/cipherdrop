import express from 'express';
import request from 'supertest';
import { afterAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../test/app';
import { env } from '../config/env';
import { errorHandler } from '../middleware/error';
import type { RateLimitsConfig } from './rateLimit';

const apps: TestApp[] = [];

afterAll(async () => {
  await Promise.all(apps.map((a) => a.close()));
});

async function limitedApp(rateLimits?: RateLimitsConfig) {
  const t = await createTestApp(rateLimits === undefined ? {} : { rateLimits });
  apps.push(t);
  const app = express();
  app.locals.ctx = t.ctx;
  app.get(
    '/limited',
    t.ctx.rateLimit({ name: 'r10-test', windowMs: 60_000, limit: 2, key: () => 'fixed-key' }),
    (_req, res) => {
      res.json({ ok: true });
    },
  );
  app.use(errorHandler);
  return { t, app };
}

describe('R10 rate-limit infrastructure', () => {
  it('limits per key in Redis under ${KEY_PREFIX}:rl:<name>: and answers 429 RATE_LIMITED with Retry-After', async () => {
    const { t, app } = await limitedApp(true);
    expect((await request(app).get('/limited')).status).toBe(200);
    expect((await request(app).get('/limited')).status).toBe(200);
    const limited = await request(app).get('/limited');
    expect(limited.status).toBe(429);
    expect(limited.body).toEqual({ error: { code: 'RATE_LIMITED', message: expect.any(String) } });
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    const keys = await t.redis.keys(`${env.KEY_PREFIX}:rl:r10-test:*`);
    expect(keys).toEqual([`${env.KEY_PREFIX}:rl:r10-test:fixed-key`]);
  });

  it('is a pass-through when RATE_LIMITS_ENABLED=false (the test default)', async () => {
    const { app } = await limitedApp();
    for (let i = 0; i < 4; i++) {
      expect((await request(app).get('/limited')).status).toBe(200);
    }
  });

  it('createApp({rateLimits}) can enable a single limiter by name', async () => {
    const { app } = await limitedApp({ 'r10-test': true });
    await request(app).get('/limited');
    await request(app).get('/limited');
    expect((await request(app).get('/limited')).status).toBe(429);
  });
});
