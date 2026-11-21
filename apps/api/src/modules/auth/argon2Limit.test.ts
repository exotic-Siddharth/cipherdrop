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

describe('a full Argon2id queue spends no per-client budget', () => {
  let c: TestApp;
  beforeAll(async () => {
    c = await createTestApp({
      env: { ARGON2_MAX_CONCURRENT: 1, ARGON2_MAX_QUEUE: 0 },
      rateLimits: { login: true, loginIp: true, register: true, reauth: true },
    });
  });
  afterAll(async () => {
    await c.close();
  });

  function holdSlotOf(app: TestApp): () => Promise<void> {
    let release!: () => void;
    const held = app.ctx.argon2.run(() => new Promise<void>((resolve) => (release = resolve)));
    return async () => {
      release();
      await held;
    };
  }

  it('an honest user who retries during a login flood can sign in once it is over', async () => {
    const user = await createUserRecord(c.prisma);
    const login = () =>
      request(c.app)
        .post('/api/auth/login')
        .set('X-Forwarded-For', '192.0.2.80')
        .send({ email: user.email, authKey: TEST_ACCOUNT.authKey });
    const release = holdSlotOf(c);
    // More than both budgets (10 per IP+email, 30 failures per client): every one is the queue's own 429.
    for (let i = 0; i < 35; i++) expectBusy(await login());
    await release();
    const ok = await login();
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
  });

  it('register and re-authentication budgets are refunded too, but their own limits still hold', async () => {
    const user = await createUserRecord(c.prisma);
    const register = () =>
      request(c.app)
        .post('/api/auth/register')
        .set('X-Forwarded-For', '192.0.2.81')
        .send({
          email: uniqueEmail('busy'),
          authKey: TEST_ACCOUNT.authKey,
          kdf: TEST_ACCOUNT.kdf,
          wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
          wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
          recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
        });
    const session = authHeader(user); // one session: the reauth budget is per session
    const wrongProof = () =>
      request(c.app)
        .delete('/api/me')
        .set('Authorization', session)
        .send({ authKey: Buffer.alloc(32, 0xa5).toString('base64url') });
    const release = holdSlotOf(c);
    for (let i = 0; i < 6; i++) expectBusy(await register()); // limit 5 per hour
    for (let i = 0; i < 11; i++) expectBusy(await wrongProof()); // limit 10 per 15 min
    await release();
    // The budgets are whole again, and still enforced.
    for (let i = 0; i < 10; i++) expect((await wrongProof()).status).toBe(403);
    const limited = await wrongProof();
    expect(limited.status).toBe(429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(ARGON2_RETRY_AFTER_SEC);
    expect((await register()).status).toBe(201);
  });
});
