/**
 * Chunk routes are exempt from the global per-IP limiter, and the per-token limiters key on whatever bearer
 * string arrives, so random tokens each got a fresh bucket. The per-IP chunkIp limiter bounds them (R10).
 */
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { id16 } from './test-utils';

describe('chunk routes per-IP limit', () => {
  let t: TestApp;
  let server: ReturnType<TestApp['app']['listen']>;
  let base = '';

  beforeAll(async () => {
    t = await createTestApp({ rateLimits: { chunkIp: true } });
    server = t.app.listen(0, '127.0.0.1');
    await new Promise<void>((r) => server.once('listening', () => r()));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    await t.close();
  });

  it('random bearer tokens cannot dodge it: 6000 chunk GETs per minute per IP, then 429', async () => {
    const url = `${base}/api/drops/${id16()}/files/${id16()}/chunks/0`;
    const total = 6100;
    const statuses = new Map<number, number>();
    let next = 0;
    const worker = async () => {
      while (next < total) {
        next += 1;
        const res = await fetch(url, {
          headers: { Authorization: `Bearer ${randomBytes(32).toString('base64url')}` },
        });
        await res.arrayBuffer();
        statuses.set(res.status, (statuses.get(res.status) ?? 0) + 1);
      }
    };
    await Promise.all(Array.from({ length: 40 }, worker));
    expect(statuses.get(401)).toBe(6000);
    expect(statuses.get(429)).toBe(total - 6000);
  }, 120_000);
});
