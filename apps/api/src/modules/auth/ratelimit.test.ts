/** R10: the prelogin, login, loginIp, loginMfa, register and recovery limiters go through ctx.rateLimit. */
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { TEST_ACCOUNT, createUserRecord, uniqueEmail } from '../../../test/factories';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp({
    rateLimits: { prelogin: true, login: true, loginMfa: true, register: true, recovery: true },
  });
});

afterAll(async () => {
  await t.close();
});

const post = (path: string, ip: string, body: object) =>
  request(t.app).post(`/api/auth${path}`).set('X-Forwarded-For', ip).send(body);

async function hitUntilLimited(send: () => Promise<request.Response>, allowed: number) {
  for (let i = 0; i < allowed; i++) expect((await send()).status).not.toBe(429);
  const limited = await send();
  expect(limited.status).toBe(429);
  expect(limited.body.error.code).toBe('RATE_LIMITED');
  expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
}

describe('auth rate limits', () => {
  it('login: 10 per 15 min per IP+email (another email from the same IP is unaffected)', async () => {
    const email = uniqueEmail('rl');
    const body = { email, authKey: TEST_ACCOUNT.authKey };
    await hitUntilLimited(() => post('/login', '192.0.2.10', body), 10);
    const other = await post('/login', '192.0.2.10', { ...body, email: uniqueEmail('rl') });
    expect(other.status).toBe(401);
    const otherIp = await post('/login', '192.0.2.11', body);
    expect(otherIp.status).toBe(401);
  });

  it('prelogin: 10 per 15 min per IP+email', async () => {
    const email = uniqueEmail('rl');
    await hitUntilLimited(() => post('/prelogin', '192.0.2.20', { email }), 10);
  });

  it('register: 5 per hour per IP', async () => {
    const send = () =>
      post('/register', '192.0.2.30', {
        email: uniqueEmail('rl'),
        authKey: TEST_ACCOUNT.authKey,
        kdf: TEST_ACCOUNT.kdf,
        wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
        wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
        recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
      });
    await hitUntilLimited(send, 5);
  });

  it('recovery/start: 5 per hour per IP', async () => {
    await hitUntilLimited(
      () =>
        post('/recovery/start', '192.0.2.40', {
          email: uniqueEmail('rl'),
          recoveryAuthKey: TEST_ACCOUNT.recoveryAuthKey,
        }),
      5,
    );
  });

  it('login/mfa: 10 per 15 min per IP', async () => {
    await hitUntilLimited(
      () => post('/login/mfa', '192.0.2.50', { mfaToken: 'x.y.z', code: '123456' }),
      10,
    );
  });
});

describe('failed logins per client (critic-1)', () => {
  let c: TestApp;
  beforeAll(async () => {
    c = await createTestApp({ rateLimits: { loginIp: true } });
  });
  afterAll(async () => {
    await c.close();
  });

  const login = (ip: string, email = uniqueEmail('spray')) =>
    request(c.app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', ip)
      .send({ email, authKey: TEST_ACCOUNT.authKey });

  it('30 failures per 15 min per IPv4 address, whatever the email; successful logins are refunded', async () => {
    const user = await createUserRecord(c.prisma);
    for (let i = 0; i < 29; i++) expect((await login('192.0.2.60')).status).toBe(401);
    for (let i = 0; i < 3; i++) expect((await login('192.0.2.60', user.email)).status).toBe(200);
    expect((await login('192.0.2.60')).status).toBe(401);
    const limited = await login('192.0.2.60');
    expect(limited.status).toBe(429);
    expect(limited.body.error.code).toBe('RATE_LIMITED');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    // Even the right password waits now; another address is unaffected.
    expect((await login('192.0.2.60', user.email)).status).toBe(429);
    expect((await login('192.0.2.61', user.email)).status).toBe(200);
  });

  it('keys IPv6 clients by /48: rotating /64s inside it does not reset the budget', async () => {
    for (let i = 0; i < 30; i++) {
      expect((await login(`2001:db8:60:${i.toString(16)}::1`)).status).toBe(401);
    }
    expect((await login('2001:db8:60:ffff::2')).status).toBe(429);
    expect((await login('2001:db8:61::1')).status).toBe(401);
  });
});
