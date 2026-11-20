/**
 * server-1: new accounts are on probation. For their first NEW_ACCOUNT_PROBATION_DAYS their quota is at most
 * NEW_ACCOUNT_QUOTA_BYTES; an admin's quota edit ends the probation at once.
 */
import { AdminUserResponseSchema, AuthSuccessSchema, MeResponseSchema } from '@cipherdrop/shared';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createAdminRecord, TEST_ACCOUNT, uniqueEmail } from '../../../test/factories';
import { createBody, fakeWrappedKey, postDrop, testClock, testFile } from '../drops/test-utils';

const DAY = 86_400_000;
const PROBATION_QUOTA = 3000;

const registerBody = () => ({
  email: uniqueEmail('probation'),
  authKey: TEST_ACCOUNT.authKey,
  kdf: TEST_ACCOUNT.kdf,
  wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
  wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
  recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
});

describe('new-account probation quota', () => {
  const clock = testClock(new Date('2026-11-20T09:00:00.000Z'));
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp({
      now: clock.now,
      env: { NEW_ACCOUNT_QUOTA_BYTES: PROBATION_QUOTA, NEW_ACCOUNT_PROBATION_DAYS: 7 },
    });
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
    clock.set(new Date('2026-11-20T09:00:00.000Z'));
  });
  afterAll(async () => {
    await resetTables(t.prisma);
    await t.close();
  });

  async function register() {
    const res = await request(t.app).post('/api/auth/register').send(registerBody());
    expect(res.status).toBe(201);
    const { user, accessToken } = AuthSuccessSchema.parse(res.body);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    return { user, row, auth: `Bearer ${accessToken}` };
  }

  const userDrop = (auth: string, plain: number) =>
    postDrop(t.app, createBody([testFile(plain)], { ownerWrappedKey: fakeWrappedKey() }), {
      Authorization: auth,
    });

  it('a new account gets the probation quota for its first days, with the end date in Me', async () => {
    const { user, row, auth } = await register();
    const ends = new Date(clock.now().getTime() + 7 * DAY).toISOString();
    // The stored quota is the default; what applies (and what Me reports) is the probation quota.
    expect(row.storageQuotaBytes).toBe(BigInt(t.ctx.env.USER_DEFAULT_QUOTA_BYTES));
    expect(row.quotaProbationEndsAt?.toISOString()).toBe(ends);
    expect(user).toMatchObject({ storageQuotaBytes: PROBATION_QUOTA, quotaProbationEndsAt: ends });
    const me = MeResponseSchema.parse(
      (await request(t.app).get('/api/me').set('Authorization', auth)).body,
    );
    expect(me.user).toMatchObject({
      storageQuotaBytes: PROBATION_QUOTA,
      quotaProbationEndsAt: ends,
    });
  });

  it('refuses a drop above the probation quota with QUOTA_EXCEEDED and the end date', async () => {
    const { auth } = await register();
    expect((await userDrop(auth, 2000)).status).toBe(201);
    const refused = await userDrop(auth, 2000);
    expect(refused.status).toBe(413);
    expect(refused.body.error).toMatchObject({
      code: 'QUOTA_EXCEEDED',
      message: expect.stringMatching(/new accounts/i),
      details: {
        quotaBytes: PROBATION_QUOTA,
        usedBytes: 2016,
        probationEndsAt: new Date(clock.now().getTime() + 7 * DAY).toISOString(),
      },
    });
  });

  it('ends on its date: the stored quota applies from then on', async () => {
    const { user, auth } = await register();
    expect((await userDrop(auth, 2000)).status).toBe(201);
    clock.advance(7 * DAY - 1000);
    expect((await userDrop(auth, 2000)).status).toBe(413);
    clock.advance(1000);
    expect((await userDrop(auth, 2000)).status).toBe(201);
    const me = await request(t.app)
      .get('/api/me')
      .set('Authorization', authHeader({ id: user.id, role: 'USER' }));
    expect(me.body.user).toMatchObject({
      storageQuotaBytes: t.ctx.env.USER_DEFAULT_QUOTA_BYTES,
      quotaProbationEndsAt: null,
    });
  });

  it("an admin's quota edit overrides it at once; a role-only edit does not", async () => {
    const admin = await createAdminRecord(t.prisma);
    const { user, auth } = await register();
    const patch = (body: object) =>
      request(t.app)
        .patch(`/api/admin/users/${user.id}`)
        .set('Authorization', authHeader(admin))
        .send(body);

    const roleOnly = AdminUserResponseSchema.parse((await patch({ role: 'USER' })).body);
    expect(roleOnly.user).toMatchObject({
      storageQuotaBytes: PROBATION_QUOTA,
      quotaProbationEndsAt: expect.any(String),
    });
    const listed = await request(t.app)
      .get('/api/admin/users')
      .set('Authorization', authHeader(admin));
    expect(listed.body.items.find((u: { id: string }) => u.id === user.id)).toMatchObject({
      storageQuotaBytes: PROBATION_QUOTA,
      quotaProbationEndsAt: expect.any(String),
    });

    const raised = AdminUserResponseSchema.parse((await patch({ storageQuotaBytes: 10_000 })).body);
    expect(raised.user).toMatchObject({ storageQuotaBytes: 10_000, quotaProbationEndsAt: null });
    expect(
      (await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } })).quotaProbationEndsAt,
    ).toBeNull();
    // Still inside the 7 days: the admin's 10,000 bytes apply, not the 3,000-byte probation quota.
    expect((await userDrop(auth, 2000)).status).toBe(201);
    expect((await userDrop(auth, 2000)).status).toBe(201);
  });

  it('an admin can also lower the quota of an account on probation below the probation quota', async () => {
    const admin = await createAdminRecord(t.prisma);
    const { user, auth } = await register();
    await request(t.app)
      .patch(`/api/admin/users/${user.id}`)
      .set('Authorization', authHeader(admin))
      .send({ storageQuotaBytes: 1000 });
    expect((await userDrop(auth, 2000)).status).toBe(413);
  });
});

describe('new-account probation opt-out', () => {
  it('NEW_ACCOUNT_PROBATION_DAYS=0: a new account gets the full quota at once', async () => {
    const t = await createTestApp({
      env: { NEW_ACCOUNT_QUOTA_BYTES: PROBATION_QUOTA, NEW_ACCOUNT_PROBATION_DAYS: 0 },
    });
    try {
      const res = await request(t.app).post('/api/auth/register').send(registerBody());
      expect(res.status).toBe(201);
      expect(res.body.user).toMatchObject({
        storageQuotaBytes: t.ctx.env.USER_DEFAULT_QUOTA_BYTES,
        quotaProbationEndsAt: null,
      });
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });

  it('is on by default: 256 MiB for 7 days', async () => {
    const t = await createTestApp();
    try {
      expect(t.ctx.env.NEW_ACCOUNT_QUOTA_BYTES).toBe(256 * 1024 ** 2);
      expect(t.ctx.env.NEW_ACCOUNT_PROBATION_DAYS).toBe(7);
      const res = await request(t.app).post('/api/auth/register').send(registerBody());
      expect(res.body.user.storageQuotaBytes).toBe(256 * 1024 ** 2);
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });
});
