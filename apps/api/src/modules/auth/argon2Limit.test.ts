/**
 * critic-1: server-side Argon2id on the request path is bounded by ctx.argon2. With every slot taken and the
 * queue full, the routes that hash or verify an account authKey answer 429 RATE_LIMITED with Retry-After at
 * once, run no Argon2id and change nothing; known and unknown emails get the same answer.
 */
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { TEST_ACCOUNT, authHeader, createUserRecord, uniqueEmail } from '../../../test/factories';
import { ARGON2_RETRY_AFTER_SEC } from '../../lib/argon2Limiter';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp({ env: { ARGON2_MAX_CONCURRENT: 1, ARGON2_MAX_QUEUE: 0 } });
});

afterAll(async () => {
  await t.close();
});

/** Take the only slot until the returned function is called. */
function holdSlot(): () => Promise<void> {
  let release!: () => void;
  const held = t.ctx.argon2.run(() => new Promise<void>((resolve) => (release = resolve)));
  return async () => {
    release();
    await held;
  };
}

const expectBusy = (res: request.Response) => {
  expect(res.status, JSON.stringify(res.body)).toBe(429);
  expect(res.body.error.code).toBe('RATE_LIMITED');
  expect(res.headers['retry-after']).toBe(String(ARGON2_RETRY_AFTER_SEC));
};

describe('Argon2id limiter on the auth routes', () => {
  it('login: 429 + Retry-After while the queue is full, for known and unknown emails alike', async () => {
    const user = await createUserRecord(t.prisma);
    const release = holdSlot();
    const login = (email: string) =>
      request(t.app).post('/api/auth/login').send({ email, authKey: TEST_ACCOUNT.authKey });
    expectBusy(await login(user.email));
    expectBusy(await login(uniqueEmail('nobody')));
    // A refused request is not a failed proof: no lockout progress, no audit event.
    const after = await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(after.failedLoginCount).toBe(0);
    expect(await t.prisma.auditEvent.count({ where: { userId: user.id } })).toBe(0);

    await release();
    const ok = await login(user.email);
    expect(ok.status).toBe(200);
    expect(ok.body.mfaRequired).toBe(false);
  });

  it('register and the signed-in re-authentication routes are bounded too', async () => {
    const user = await createUserRecord(t.prisma);
    const release = holdSlot();
    const email = uniqueEmail('busy');
    expectBusy(
      await request(t.app).post('/api/auth/register').send({
        email,
        authKey: TEST_ACCOUNT.authKey,
        kdf: TEST_ACCOUNT.kdf,
        wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
        wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
        recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
      }),
    );
    expect(await t.prisma.user.count({ where: { email } })).toBe(0);
    expectBusy(
      await request(t.app)
        .delete('/api/me')
        .set('Authorization', authHeader(user))
        .send({ authKey: TEST_ACCOUNT.authKey }),
    );
    expect(await t.prisma.user.count({ where: { id: user.id } })).toBe(1);
    await release();
  });
});
