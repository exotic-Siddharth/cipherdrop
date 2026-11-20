/**
 * server-1: the rolling per-client byte budget for anonymous drops (ANON_BYTES_PER_CLIENT per
 * ANON_BYTES_WINDOW_HOURS, per IPv4 address or IPv6 /48). Beyond it: 429 UPLOAD_BUDGET_EXCEEDED with a
 * Retry-After that says when enough bytes leave the window.
 */
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createUserRecord } from '../../../test/factories';
import { anonBytesKey } from '../../lib/byteBudget';
import {
  createBody,
  fakeWrappedKey,
  HOUR,
  metricValue,
  postDrop,
  testClock,
  testFile,
} from './test-utils';

/** testFile(2000) is 2016 bytes of ciphertext: a 5000-byte budget takes two of them, not three. */
const FILE = 2000;
const CT = 2016;
const BUDGET = 5000;

const from = (ip: string) => ({ 'X-Forwarded-For': ip });
const anonDrop = (t: TestApp, ip: string, plain = FILE) =>
  postDrop(t.app, createBody([testFile(plain)]), from(ip));

describe('anonymous byte budget per client', () => {
  const clock = testClock(new Date('2026-11-20T08:00:00.000Z'));
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp({
      now: clock.now,
      env: { ANON_BYTES_PER_CLIENT: BUDGET, ANON_BYTES_WINDOW_HOURS: 24 },
    });
    await resetTables(t.prisma);
  });
  afterEach(async () => {
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });

  it('refuses the create that would exceed the budget with 429, Retry-After and the budget', async () => {
    const ip = '198.51.100.10';
    expect((await anonDrop(t, ip)).status).toBe(201);
    clock.advance(HOUR);
    expect((await anonDrop(t, ip)).status).toBe(201);
    clock.advance(HOUR);
    const before = await metricValue(t.app, 'drops_refused_total', 'reason="client_budget"');

    const refused = await anonDrop(t, ip);
    expect(refused.status).toBe(429);
    expect(refused.body.error).toEqual({
      code: 'UPLOAD_BUDGET_EXCEEDED',
      message: expect.stringMatching(/sign in/i),
      details: { limitBytes: BUDGET, windowHours: 24 },
    });
    // The first drop leaves the window 24 h after it was created, 22 h from now.
    expect(Number(refused.headers['retry-after'])).toBe(22 * 3600);
    expect(await metricValue(t.app, 'drops_refused_total', 'reason="client_budget"')).toBe(
      before + 1,
    );
    // A smaller drop that still fits is accepted: the budget counts bytes, not drops.
    expect((await anonDrop(t, ip, 500)).status).toBe(201);
  });

  it('is a rolling window: bytes come back as their creates age out, not at a fixed reset', async () => {
    const ip = '198.51.100.11';
    expect((await anonDrop(t, ip)).status).toBe(201);
    clock.advance(HOUR);
    expect((await anonDrop(t, ip)).status).toBe(201);
    clock.advance(23 * HOUR - 1000);
    expect((await anonDrop(t, ip)).status).toBe(429);
    clock.advance(1000); // the first create is now 24 h old
    expect((await anonDrop(t, ip)).status).toBe(201);
    const refused = await anonDrop(t, ip);
    expect(refused.status).toBe(429);
    // The second create (made 1 h after the first) is next to leave.
    expect(Number(refused.headers['retry-after'])).toBe(3600);
  });

  it('covers an IPv6 /48 whichever /64 the creates come from; other clients are unaffected', async () => {
    expect((await anonDrop(t, '2001:db8:40:1::1')).status).toBe(201);
    expect((await anonDrop(t, '2001:db8:40:2::1')).status).toBe(201);
    expect((await anonDrop(t, '2001:db8:40:3::1')).status).toBe(429);
    expect((await anonDrop(t, '2001:db8:41::1')).status).toBe(201);
    expect((await anonDrop(t, '198.51.100.12')).status).toBe(201);
  });

  it('does not apply to signed-in senders', async () => {
    const ip = '198.51.100.13';
    const user = await createUserRecord(t.prisma);
    for (let i = 0; i < 4; i++) {
      const res = await postDrop(
        t.app,
        createBody([testFile(FILE)], { ownerWrappedKey: fakeWrappedKey() }),
        { ...from(ip), Authorization: authHeader(user) },
      );
      expect(res.status).toBe(201);
    }
    expect((await anonDrop(t, ip)).status).toBe(201);
  });

  it('parallel creates from one client cannot overshoot it', async () => {
    const ip = '198.51.100.14';
    const results = await Promise.all(Array.from({ length: 8 }, () => anonDrop(t, ip)));
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 201)).toHaveLength(2);
    expect(statuses.filter((s) => s === 429)).toHaveLength(6);
  });

  it('spends nothing on a create refused for its shape', async () => {
    const ip = '198.51.100.15';
    for (let i = 0; i < 3; i++) {
      const bad = await postDrop(
        t.app,
        createBody([testFile(FILE)], { maxDownloads: 50 }),
        from(ip),
      );
      expect(bad.status).toBe(400);
    }
    expect((await anonDrop(t, ip)).status).toBe(201);
    expect((await anonDrop(t, ip)).status).toBe(201);
  });

  it('keeps no drop id and no IP address beyond the client key, and expires with the window', async () => {
    const ip = '198.51.100.16';
    const res = await anonDrop(t, ip);
    expect(res.status).toBe(201);
    const key = anonBytesKey(ip);
    const members = await t.redis.zrange(key, 0, -1);
    expect(members).toHaveLength(1);
    expect(members[0]).toMatch(new RegExp(`^[A-Za-z0-9_-]{16}:${CT}$`));
    expect(members[0]).not.toContain(res.body.dropId);
    const ttl = await t.redis.pttl(key);
    expect(ttl).toBeGreaterThan(23 * HOUR);
    expect(ttl).toBeLessThanOrEqual(24 * HOUR);
  });
});

describe('anonymous byte budget refunds and opt-out', () => {
  it('gives the bytes back when the create fails after the reservation (anonymous pool full)', async () => {
    const t = await createTestApp({
      env: { ANON_BYTES_PER_CLIENT: BUDGET, ANON_TOTAL_PENDING_BYTES: 2500 },
    });
    try {
      await resetTables(t.prisma);
      const ip = '198.51.100.20';
      const first = await anonDrop(t, ip);
      expect(first.status).toBe(201);
      // The pool is full: 413, and the 2016 bytes reserved for it go back to the client.
      const full = await anonDrop(t, ip);
      expect(full.status).toBe(413);
      expect(full.body.error.code).toBe('QUOTA_EXCEEDED');
      await t.prisma.drop.update({
        where: { id: first.body.dropId as string },
        data: { blobsDeletedAt: new Date() },
      });
      // 2016 + 2016 fits the 5000-byte budget only if the refused create was refunded.
      expect((await anonDrop(t, ip)).status).toBe(201);
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });

  it('ANON_BYTES_PER_CLIENT=0 turns it off', async () => {
    const t = await createTestApp({ env: { ANON_BYTES_PER_CLIENT: 0 } });
    try {
      await resetTables(t.prisma);
      for (let i = 0; i < 4; i++) {
        const res = await request(t.app)
          .post('/api/drops')
          .set(from('198.51.100.21'))
          .send(createBody([testFile(FILE)]));
        expect(res.status).toBe(201);
      }
      expect(await t.redis.exists(anonBytesKey('198.51.100.21'))).toBe(0);
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });

  it('is on by default: 1 GiB per client per 24 hours', async () => {
    const t = await createTestApp();
    try {
      expect(t.ctx.env.ANON_BYTES_PER_CLIENT).toBe(1024 ** 3);
      expect(t.ctx.env.ANON_BYTES_WINDOW_HOURS).toBe(24);
      await resetTables(t.prisma);
      expect((await anonDrop(t, '198.51.100.22')).status).toBe(201);
      expect(await t.redis.zcard(anonBytesKey('198.51.100.22'))).toBe(1);
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });
});
