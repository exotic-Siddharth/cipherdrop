/**
 * server-1: the rolling per-client byte budget for anonymous drops (ANON_BYTES_PER_CLIENT per
 * ANON_BYTES_WINDOW_HOURS, per IPv4 address or IPv6 /48). Beyond it: 429 UPLOAD_BUDGET_EXCEEDED with a
 * Retry-After that says when enough bytes leave the window. Redis keeps only hourly MiB totals per client.
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

const MiB = 1024 * 1024;
/** testFile(2000) is 2016 bytes of ciphertext, which the budget rounds up to 1 MiB. */
const FILE = 2000;
/** About 1.5 MiB of ciphertext: 2 MiB of budget. */
const FILE_2MIB = 1.5 * MiB;
/** Takes two 1-MiB creates, not three. */
const BUDGET = 2 * MiB;
/** 08:30 UTC: the hour bucket of a create made now is 08:00-09:00. */
const START = new Date('2026-11-20T08:30:00.000Z');
const hourOf = (d: Date) => String(Math.floor(d.getTime() / HOUR));

const from = (ip: string) => ({ 'X-Forwarded-For': ip });
const anonDrop = (t: TestApp, ip: string, plain = FILE) =>
  postDrop(t.app, createBody([testFile(plain)]), from(ip));

describe('anonymous byte budget per client', () => {
  const clock = testClock(START);
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp({
      now: clock.now,
      env: { ANON_BYTES_PER_CLIENT: BUDGET, ANON_BYTES_WINDOW_HOURS: 24 },
    });
    await resetTables(t.prisma);
  });
  afterEach(async () => {
    clock.set(START);
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });

  it('refuses the create that would exceed the budget with 429, Retry-After and the budget', async () => {
    const ip = '198.51.100.10';
    const budget3 = await createTestApp({
      now: clock.now,
      env: { ANON_BYTES_PER_CLIENT: 3 * MiB, ANON_BYTES_WINDOW_HOURS: 24 },
    });
    try {
      expect((await anonDrop(budget3, ip)).status).toBe(201); // 08:30, 1 MiB
      clock.advance(HOUR);
      expect((await anonDrop(budget3, ip)).status).toBe(201); // 09:30, 1 MiB
      clock.advance(HOUR);
      const before = await metricValue(
        budget3.app,
        'drops_refused_total',
        'reason="client_budget"',
      );

      const refused = await anonDrop(budget3, ip, FILE_2MIB); // 10:30, 2 MiB: 4 > 3
      expect(refused.status).toBe(429);
      expect(refused.body.error).toEqual({
        code: 'UPLOAD_BUDGET_EXCEEDED',
        message: expect.stringMatching(/sign in/i),
        details: { limitBytes: 3 * MiB, windowHours: 24 },
      });
      // The 08:00 hour counts for 24 full hours after it: it leaves at 09:00 tomorrow, 22.5 h from now.
      expect(Number(refused.headers['retry-after'])).toBe(22.5 * 3600);
      expect(await metricValue(budget3.app, 'drops_refused_total', 'reason="client_budget"')).toBe(
        before + 1,
      );
      // A smaller drop that still fits is accepted: the budget counts bytes, not drops.
      expect((await anonDrop(budget3, ip)).status).toBe(201);
    } finally {
      await budget3.close();
    }
  });

  it('counts every create as whole MiB, rounded up', async () => {
    const ip = '198.51.100.17';
    // Two 2016-byte drops fill a 2 MiB budget: each takes 1 MiB.
    expect((await anonDrop(t, ip)).status).toBe(201);
    expect((await anonDrop(t, ip)).status).toBe(201);
    expect((await anonDrop(t, ip, 1)).status).toBe(429);
    // A 1.5 MiB drop takes 2 MiB: alone it fits the budget of another client, with anything else it does not.
    const other = '198.51.100.18';
    expect((await anonDrop(t, other, FILE_2MIB)).status).toBe(201);
    expect((await anonDrop(t, other, 1)).status).toBe(429);
  });

  it('is a rolling window of hours: bytes come back as their hour ages out, not at a fixed reset', async () => {
    const ip = '198.51.100.11';
    expect((await anonDrop(t, ip)).status).toBe(201); // 08:30, hour 08
    clock.advance(HOUR);
    expect((await anonDrop(t, ip)).status).toBe(201); // 09:30, hour 09
    // Tomorrow 08:59:59, the 08:00 hour still counts (24 full hours after it have not passed).
    clock.set(new Date('2026-11-21T08:59:59.000Z'));
    expect((await anonDrop(t, ip)).status).toBe(429);
    clock.set(new Date('2026-11-21T09:00:00.000Z')); // the 08:00 hour has left the window
    expect((await anonDrop(t, ip)).status).toBe(201);
    const refused = await anonDrop(t, ip);
    expect(refused.status).toBe(429);
    // The 09:00 hour is next to leave, at 10:00.
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

  it('stores per client only MiB totals per hour (no create time, size or drop id); expires with the window', async () => {
    const ip = '198.51.100.16';
    const first = await anonDrop(t, ip);
    expect(first.status).toBe(201);
    clock.advance(20 * 60_000); // 08:50, same hour
    const second = await anonDrop(t, ip);
    expect(second.status).toBe(201);
    const key = anonBytesKey(ip);
    // One field for the hour, its value the MiB of both creates together: the two 2016-byte creates, their
    // times and their ids are not in Redis, so a Drop row matches only "a create of up to 1 MiB that hour".
    expect(await t.redis.hgetall(key)).toEqual({ [hourOf(START)]: '2' });
    expect(await t.redis.type(key)).toBe('hash');
    // The key goes when the 08:00 hour leaves the window, at 09:00 tomorrow: 24 h 10 min from 08:50.
    const ttl = await t.redis.pttl(key);
    expect(ttl).toBeGreaterThan(24 * HOUR);
    expect(ttl).toBeLessThanOrEqual(24 * HOUR + 10 * 60_000);
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
      // The pool is full: 413, and the 1 MiB reserved for it goes back to the client.
      const full = await anonDrop(t, ip);
      expect(full.status).toBe(413);
      expect(full.body.error.code).toBe('QUOTA_EXCEEDED');
      await t.prisma.drop.update({
        where: { id: first.body.dropId as string },
        data: { blobsDeletedAt: new Date() },
      });
      // 1 MiB + 1 MiB fits the 2 MiB budget only if the refused create was refunded.
      expect((await anonDrop(t, ip)).status).toBe(201);
      expect(Object.values(await t.redis.hgetall(anonBytesKey(ip)))).toEqual(['2']);
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
      expect(Object.values(await t.redis.hgetall(anonBytesKey('198.51.100.22')))).toEqual(['1']);
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });
});
