import { createHmac } from 'node:crypto';
import {
  AAD,
  KDF_DEFAULT,
  KDF_MIN,
  b64urlEncode,
  createRecoveryBundle,
  deriveAccountKeys,
  deriveRecoveryKeys,
  parseRecoveryKey,
  rewrapForNewPassword,
  unwrapKey,
  type KdfParams,
} from '@cipherdrop/crypto';
import {
  AuthSuccessSchema,
  LoginResponseSchema,
  PreloginResponseSchema,
  RecoveryStartResponseSchema,
  RefreshResponseSchema,
  SessionListResponseSchema,
  VaultSchema,
} from '@cipherdrop/shared';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { TEST_ACCOUNT, createUserRecord, uniqueEmail } from '../../../test/factories';
import { sha256B64url } from '../../lib/hash';
import { isSidDenylisted } from '../../lib/redis';
import { REFRESH_GRACE_MS } from './service';
import {
  bearer,
  cookieFrom,
  loginViaApi,
  newSession,
  refreshSetCookie,
  refreshTokenFrom,
  registerViaApi,
  sidOf,
  type RegisteredUser,
} from './testkit';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
});

afterAll(async () => {
  await t.close();
});

const GENERIC_LOGIN = { error: { code: 'UNAUTHORIZED', message: 'Invalid email or password' } };

const actionsOf = async (userId: string) =>
  (await t.prisma.auditEvent.findMany({ where: { userId }, orderBy: { createdAt: 'asc' } })).map(
    (e) => e.action,
  );

const vault = (accessToken: string) =>
  request(t.app).get('/api/auth/vault').set('Authorization', bearer(accessToken));
const refresh = (cookie: string) => request(t.app).post('/api/auth/refresh').set('Cookie', cookie);

/** Client side: recover the raw account key from the vault material with the password. */
async function unwrapAccountKey(password: string, accessToken: string): Promise<Uint8Array> {
  const res = await vault(accessToken);
  expect(res.status).toBe(200);
  const { encKey } = await deriveAccountKeys(password, res.body.kdf as KdfParams);
  return unwrapKey(encKey, res.body.wrappedAccountKey as string, AAD.WRAP_ACCOUNT);
}

describe('POST /auth/prelogin', () => {
  it('returns the stored kdf for a known email', async () => {
    const user = await createUserRecord(t.prisma);
    const res = await request(t.app).post('/api/auth/prelogin').send({ email: user.email });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ kdf: TEST_ACCOUNT.kdf });
  });

  it('returns a deterministic HMAC fake salt with default params for an unknown email', async () => {
    const email = uniqueEmail('ghost');
    const expectedSalt = createHmac('sha256', process.env.PRELOGIN_SECRET as string)
      .update(email.toLowerCase())
      .digest()
      .subarray(0, 16)
      .toString('base64url');
    const one = await request(t.app).post('/api/auth/prelogin').send({ email });
    const two = await request(t.app)
      .post('/api/auth/prelogin')
      .send({ email: `  ${email.toUpperCase()} ` });
    const other = await request(t.app)
      .post('/api/auth/prelogin')
      .send({ email: uniqueEmail('ghost') });
    expect(one.status).toBe(200);
    expect(PreloginResponseSchema.strict().parse(one.body)).toEqual({
      kdf: { salt: expectedSalt, ...KDF_DEFAULT },
    });
    expect(Object.keys(one.body.kdf).sort()).toEqual(Object.keys(TEST_ACCOUNT.kdf).sort());
    expect(two.body).toEqual(one.body);
    expect(other.body.kdf.salt).not.toBe(one.body.kdf.salt);
  });
});

describe('POST /auth/register', () => {
  it('201 AuthSuccess, sets the refresh cookie, stores only an Argon2id hash and audits', async () => {
    const u = await registerViaApi(t.app);
    expect(AuthSuccessSchema.parse({ user: u.user, accessToken: u.accessToken })).toBeTruthy();
    expect(u.user).toMatchObject({
      email: u.email,
      role: 'USER',
      totpEnabled: false,
      autoLockMinutes: 15,
      storageUsedBytes: 0,
    });
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.authKeyHash.startsWith('$argon2id$')).toBe(true);
    expect(row.authKeyHash).not.toContain(u.authKey);
    expect(row.wrappedAccountKey).toBe(u.bundle.wrappedAccountKey);
    expect(row.recoveryAuthHash).toBe(u.bundle.recoveryAuthHash);
    expect(await actionsOf(u.user.id)).toEqual(['REGISTER']);
  });

  it('sets cd_rt as httpOnly, SameSite=Strict, Path=/api/auth', async () => {
    const bundleUser = await registerViaApi(t.app);
    const res = await refresh(bundleUser.cookie);
    const setCookie = refreshSetCookie(res) ?? '';
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).toMatch(/Path=\/api\/auth/);
    expect(setCookie).toMatch(/Expires=/);
  });

  it('409 for a duplicate email (case-insensitive)', async () => {
    const u = await registerViaApi(t.app);
    const res = await request(t.app).post('/api/auth/register').send({
      email: u.email.toUpperCase(),
      authKey: u.authKey,
      kdf: u.bundle.kdf,
      wrappedAccountKey: u.bundle.wrappedAccountKey,
      wrappedAccountKeyRecovery: u.bundle.wrappedAccountKeyRecovery,
      recoveryAuthHash: u.bundle.recoveryAuthHash,
    });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONFLICT');
  });

  it('400 for a kdf weaker than KDF_MIN or an authKey that is not 32 bytes', async () => {
    const body = {
      email: uniqueEmail(),
      authKey: TEST_ACCOUNT.authKey,
      kdf: { ...TEST_ACCOUNT.kdf },
      wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
      wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
      recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
    };
    const weak = await request(t.app)
      .post('/api/auth/register')
      .send({ ...body, kdf: { ...body.kdf, memoryKiB: KDF_MIN.memoryKiB - 1 } });
    expect(weak.status).toBe(400);
    expect(weak.body.error.code).toBe('VALIDATION_ERROR');
    const fewIterations = await request(t.app)
      .post('/api/auth/register')
      .send({ ...body, kdf: { ...body.kdf, iterations: 1 } });
    expect(fewIterations.status).toBe(400);
    const shortKey = await request(t.app)
      .post('/api/auth/register')
      .send({ ...body, authKey: Buffer.alloc(31, 1).toString('base64url') });
    expect(shortKey.status).toBe(400);
    expect(await t.prisma.user.count({ where: { email: body.email } })).toBe(0);
  });
});

describe('POST /auth/login', () => {
  it('logs in with the client-derived authKey and audits LOGIN_SUCCESS', async () => {
    const u = await registerViaApi(t.app);
    const res = await loginViaApi(t.app, u.email, u.password);
    expect(res.status).toBe(200);
    const body = LoginResponseSchema.parse(res.body);
    expect(body.mfaRequired).toBe(false);
    expect(refreshTokenFrom(res)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const access = res.body.accessToken as string;
    expect((await vault(access)).status).toBe(200);
    expect(await actionsOf(u.user.id)).toEqual(['REGISTER', 'LOGIN_SUCCESS']);
  });

  it('wrong authKey and unknown email get the same generic 401', async () => {
    const u = await registerViaApi(t.app);
    const wrong = await request(t.app)
      .post('/api/auth/login')
      .send({ email: u.email, authKey: TEST_ACCOUNT.authKey });
    const unknown = await request(t.app)
      .post('/api/auth/login')
      .send({ email: uniqueEmail('nobody'), authKey: TEST_ACCOUNT.authKey });
    expect(wrong.status).toBe(401);
    expect(wrong.body).toEqual(GENERIC_LOGIN);
    expect(unknown.status).toBe(401);
    expect(unknown.body).toEqual(GENERIC_LOGIN);
    expect(refreshTokenFrom(wrong)).toBeNull();
    expect(await actionsOf(u.user.id)).toEqual(['REGISTER', 'LOGIN_FAILURE']);
  });

  it('400 when the authKey does not decode to 32 bytes', async () => {
    const res = await request(t.app)
      .post('/api/auth/login')
      .send({ email: uniqueEmail(), authKey: 'AAAA' });
    expect(res.status).toBe(400);
  });

  it('locks the account for 15 min after 10 consecutive failures, with the same generic message', async () => {
    let now = Date.now();
    const clocked = await createTestApp({ now: () => new Date(now) });
    try {
      const user = await createUserRecord(clocked.prisma);
      const login = (authKey: string) =>
        request(clocked.app).post('/api/auth/login').send({ email: user.email, authKey });
      const wrongKey = Buffer.alloc(32, 0xee).toString('base64url');
      for (let i = 0; i < 9; i++) expect((await login(wrongKey)).status).toBe(401);
      // A success before the 10th failure resets the counter.
      expect((await login(TEST_ACCOUNT.authKey)).status).toBe(200);
      for (let i = 0; i < 10; i++) {
        const res = await login(wrongKey);
        expect(res.status).toBe(401);
        expect(res.body).toEqual(GENERIC_LOGIN);
      }
      const locked = await login(TEST_ACCOUNT.authKey);
      expect(locked.status).toBe(401);
      expect(locked.body).toEqual(GENERIC_LOGIN);
      const actions = (
        await clocked.prisma.auditEvent.findMany({ where: { userId: user.id } })
      ).map((e) => e.action);
      expect(actions.filter((a) => a === 'LOGIN_LOCKED')).toHaveLength(1);

      now += 15 * 60_000 + 1000;
      const after = await login(TEST_ACCOUNT.authKey);
      expect(after.status).toBe(200);
      const row = await clocked.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(row.failedLoginCount).toBe(0);
    } finally {
      await clocked.close();
    }
  });
});

describe('POST /auth/refresh and /auth/logout', () => {
  let u: RegisteredUser;
  beforeAll(async () => {
    u = await registerViaApi(t.app);
  });

  it('rotates the refresh cookie and issues a working access token with iat/exp', async () => {
    const s = await newSession(t.app, u);
    const res = await refresh(s.cookie);
    expect(res.status).toBe(200);
    const body = RefreshResponseSchema.parse(res.body);
    expect(body.user.id).toBe(u.user.id);
    const next = cookieFrom(res);
    expect(next).not.toBe(s.cookie);
    expect(sidOf(body.accessToken)).toBe(s.sid);
    const claims = JSON.parse(
      Buffer.from(body.accessToken.split('.')[1] ?? '', 'base64url').toString(),
    ) as { iat: number; exp: number };
    expect(claims.exp - claims.iat).toBe(900);
    expect((await vault(body.accessToken)).status).toBe(200);
    expect((await refresh(next)).status).toBe(200);
  });

  it('a failure while issuing the successor leaves the presented token usable (no false reuse)', async () => {
    const s = await newSession(t.app, u);
    // One-shot rejection, then the real $transaction (no mockRestore: it breaks the client Proxy).
    const real = t.prisma.$transaction.bind(t.prisma);
    vi.spyOn(t.prisma, '$transaction')
      .mockRejectedValueOnce(new Error('db blip'))
      .mockImplementation(real as never);
    expect((await refresh(s.cookie)).status).toBe(500);
    const retry = await refresh(s.cookie);
    expect(retry.status).toBe(200);
    const session = await t.prisma.session.findUniqueOrThrow({ where: { id: s.sid } });
    expect(session.revokedAt).toBeNull();
    expect(
      await t.prisma.auditEvent.count({
        where: {
          userId: u.user.id,
          action: 'SESSION_REUSE_DETECTED',
          metadata: { path: ['sessionId'], equals: s.sid },
        },
      }),
    ).toBe(0);
  });

  it('reuse of a rotated token revokes the session, denylists its sid and audits it', async () => {
    const s = await newSession(t.app, u);
    const first = await refresh(s.cookie);
    expect(first.status).toBe(200);
    const childAccess = first.body.accessToken as string;
    // The child is used, so replaying the parent is reuse even inside the lost-response grace window.
    const second = await refresh(cookieFrom(first));
    expect(second.status).toBe(200);
    const grandchild = cookieFrom(second);

    const reuse = await refresh(s.cookie);
    expect(reuse.status).toBe(401);
    const session = await t.prisma.session.findUniqueOrThrow({ where: { id: s.sid } });
    expect(session.revokedAt).not.toBeNull();
    expect(await isSidDenylisted(t.redis, s.sid)).toBe(true);
    // The whole token family is dead: the latest token and the access tokens of the session.
    expect((await refresh(grandchild)).status).toBe(401);
    expect((await vault(childAccess)).status).toBe(401);
    expect((await vault(s.accessToken)).status).toBe(401);
    const reuseEvents = await t.prisma.auditEvent.count({
      where: { userId: u.user.id, action: 'SESSION_REUSE_DETECTED' },
    });
    expect(reuseEvents).toBe(1);
  });

  it('401 without a cookie or with an unknown token', async () => {
    expect((await request(t.app).post('/api/auth/refresh')).status).toBe(401);
    expect((await refresh('cd_rt=not-a-token')).status).toBe(401);
    const unknown = `cd_rt=${Buffer.alloc(32, 3).toString('base64url')}`;
    const res = await refresh(unknown);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('a revoked (denylisted) sid is rejected immediately, before the access token expires', async () => {
    const a = await newSession(t.app, u);
    const b = await newSession(t.app, u);
    expect((await vault(b.accessToken)).status).toBe(200);
    const del = await request(t.app)
      .delete(`/api/auth/sessions/${b.sid}`)
      .set('Authorization', bearer(a.accessToken));
    expect(del.status).toBe(204);
    expect((await vault(b.accessToken)).status).toBe(401);
    expect((await refresh(b.cookie)).status).toBe(401);
    expect((await vault(a.accessToken)).status).toBe(200);
  });

  it('logout revokes the session, clears the cookie and audits LOGOUT', async () => {
    const s = await newSession(t.app, u);
    const res = await request(t.app).post('/api/auth/logout').set('Cookie', s.cookie);
    expect(res.status).toBe(204);
    expect(refreshSetCookie(res)).toMatch(/^cd_rt=;/);
    expect((await refresh(s.cookie)).status).toBe(401);
    expect((await vault(s.accessToken)).status).toBe(401);
    expect(
      await t.prisma.auditEvent.count({ where: { userId: u.user.id, action: 'LOGOUT' } }),
    ).toBe(1);
    // Logging out without a cookie is still a 204.
    expect((await request(t.app).post('/api/auth/logout')).status).toBe(204);
  });
});

describe('GET /auth/vault', () => {
  it('returns the wrapped account key and kdf, which unwrap to the account key', async () => {
    const u = await registerViaApi(t.app);
    const res = await vault(u.accessToken);
    expect(VaultSchema.strict().parse(res.body)).toEqual({
      wrappedAccountKey: u.bundle.wrappedAccountKey,
      kdf: u.bundle.kdf,
    });
    const ak = await unwrapAccountKey(u.password, u.accessToken);
    expect(Buffer.from(ak).equals(Buffer.from(u.bundle.accountKey))).toBe(true);
    expect((await request(t.app).get('/api/auth/vault')).status).toBe(401);
  });
});

describe('POST /auth/password', () => {
  it('succeeds with the correct currentAuthKey; revokes other sessions and denylists their sid', async () => {
    const u = await registerViaApi(t.app);
    const other = await newSession(t.app, u);
    const newPassword = `${u.password} (new)`;
    const rewrapped = await rewrapForNewPassword(u.bundle.accountKey, newPassword, KDF_MIN);

    const res = await request(t.app)
      .post('/api/auth/password')
      .set('Authorization', bearer(u.accessToken))
      .send({
        currentAuthKey: u.authKey,
        newAuthKey: b64urlEncode(rewrapped.authKey),
        kdf: rewrapped.kdf,
        wrappedAccountKey: rewrapped.wrappedAccountKey,
      });
    expect(res.status).toBe(204);

    // Review Focus 5: the other device is out immediately, by access token and by refresh.
    expect(await isSidDenylisted(t.redis, other.sid)).toBe(true);
    expect((await vault(other.accessToken)).status).toBe(401);
    expect((await refresh(other.cookie)).status).toBe(401);
    const otherRow = await t.prisma.session.findUniqueOrThrow({ where: { id: other.sid } });
    expect(otherRow.revokedAt).not.toBeNull();
    // The current session stays signed in.
    expect((await vault(u.accessToken)).status).toBe(200);
    expect((await refresh(u.cookie)).status).toBe(200);

    // Old password no longer works, the new one does, and the vault still opens to the SAME account key.
    expect((await loginViaApi(t.app, u.email, u.password)).status).toBe(401);
    const fresh = await newSession(t.app, { email: u.email, password: newPassword });
    const ak = await unwrapAccountKey(newPassword, fresh.accessToken);
    expect(Buffer.from(ak).equals(Buffer.from(u.bundle.accountKey))).toBe(true);
    expect(await actionsOf(u.user.id)).toContain('PASSWORD_CHANGED');
  });

  it('403 with a wrong currentAuthKey; nothing changes and no session is revoked', async () => {
    const u = await registerViaApi(t.app);
    const other = await newSession(t.app, u);
    const before = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    const res = await request(t.app)
      .post('/api/auth/password')
      .set('Authorization', bearer(u.accessToken))
      .send({
        currentAuthKey: TEST_ACCOUNT.authKey,
        newAuthKey: TEST_ACCOUNT.authKey,
        kdf: TEST_ACCOUNT.kdf,
        wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
      });
    expect(res.status).toBe(403);
    const after = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(after.authKeyHash).toBe(before.authKeyHash);
    expect(after.wrappedAccountKey).toBe(before.wrappedAccountKey);
    expect((await vault(other.accessToken)).status).toBe(200);
  });
});

describe('account recovery', () => {
  /** Client side: the recovery auth key (b64url) and the recovery wrapping key from the shown recovery key. */
  async function recoveryClient(recoveryKey: string) {
    const keys = await deriveRecoveryKeys(parseRecoveryKey(recoveryKey));
    return { encKey: keys.encKey, recoveryAuthKey: b64urlEncode(keys.authKey) };
  }
  const start = (email: string, recoveryAuthKey: string) =>
    request(t.app).post('/api/auth/recovery/start').send({ email, recoveryAuthKey });

  it('start: right key -> token + wrapped key (unwraps to AK); wrong key or unknown email -> same 401', async () => {
    const u = await registerViaApi(t.app);
    const client = await recoveryClient(u.bundle.recoveryKey);
    const ok = await start(u.email, client.recoveryAuthKey);
    expect(ok.status).toBe(200);
    const body = RecoveryStartResponseSchema.parse(ok.body);
    expect(body.mfaRequired).toBe(false);
    const ak = await unwrapKey(client.encKey, body.wrappedAccountKeyRecovery, AAD.WRAP_RECOVERY);
    expect(Buffer.from(ak).equals(Buffer.from(u.bundle.accountKey))).toBe(true);

    const wrong = await start(u.email, TEST_ACCOUNT.recoveryAuthKey);
    const unknown = await start(uniqueEmail('nobody'), client.recoveryAuthKey);
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
    expect(wrong.body.error.code).toBe('UNAUTHORIZED');
  });

  it('complete: rotates the recovery fields, revokes every session, signs in and audits', async () => {
    const u = await registerViaApi(t.app);
    const other = await newSession(t.app, u);
    const client = await recoveryClient(u.bundle.recoveryKey);
    const started = await start(u.email, client.recoveryAuthKey);
    const ak = await unwrapKey(
      client.encKey,
      started.body.wrappedAccountKeyRecovery as string,
      AAD.WRAP_RECOVERY,
    );
    const newPassword = `${u.password} (recovered)`;
    const rewrapped = await rewrapForNewPassword(ak, newPassword, KDF_MIN);
    const recovery = await createRecoveryBundle(ak);
    const completeBody = {
      recoveryToken: started.body.recoveryToken as string,
      newAuthKey: b64urlEncode(rewrapped.authKey),
      kdf: rewrapped.kdf,
      wrappedAccountKey: rewrapped.wrappedAccountKey,
      wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
      recoveryAuthHash: recovery.recoveryAuthHash,
    };

    const res = await request(t.app).post('/api/auth/recovery/complete').send(completeBody);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const auth = AuthSuccessSchema.parse(res.body);
    expect(refreshTokenFrom(res)).not.toBeNull();

    // All previous sessions are revoked and denylisted.
    for (const s of [other, { accessToken: u.accessToken, cookie: u.cookie }]) {
      expect((await vault(s.accessToken)).status).toBe(401);
      expect((await refresh(s.cookie)).status).toBe(401);
    }
    expect(await t.prisma.session.count({ where: { userId: u.user.id, revokedAt: null } })).toBe(1);
    // The new session works and the recovery fields were rotated.
    expect((await vault(auth.accessToken)).status).toBe(200);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.recoveryAuthHash).toBe(recovery.recoveryAuthHash);
    expect(row.wrappedAccountKeyRecovery).toBe(recovery.wrappedAccountKeyRecovery);
    expect(await actionsOf(u.user.id)).toContain('RECOVERY_USED');

    // The recovery token is single-use and the old recovery key is dead; the new one works.
    expect(
      (await request(t.app).post('/api/auth/recovery/complete').send(completeBody)).status,
    ).toBe(401);
    expect((await start(u.email, client.recoveryAuthKey)).status).toBe(401);
    const nextClient = await recoveryClient(recovery.recoveryKey);
    expect((await start(u.email, nextClient.recoveryAuthKey)).status).toBe(200);
    // The new password logs in.
    expect((await loginViaApi(t.app, u.email, newPassword)).status).toBe(200);
  });

  it('complete refuses to keep the old recovery key (400) and rejects a forged token (401)', async () => {
    const u = await registerViaApi(t.app);
    const client = await recoveryClient(u.bundle.recoveryKey);
    const started = await start(u.email, client.recoveryAuthKey);
    const body = {
      recoveryToken: started.body.recoveryToken as string,
      newAuthKey: TEST_ACCOUNT.authKey,
      kdf: TEST_ACCOUNT.kdf,
      wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
      wrappedAccountKeyRecovery: u.bundle.wrappedAccountKeyRecovery,
      recoveryAuthHash: u.bundle.recoveryAuthHash,
    };
    const same = await request(t.app).post('/api/auth/recovery/complete').send(body);
    expect(same.status).toBe(400);
    const forged = await request(t.app)
      .post('/api/auth/recovery/complete')
      .send({
        ...body,
        recoveryToken: u.accessToken,
        recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
      });
    expect(forged.status).toBe(401);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.recoveryAuthHash).toBe(u.bundle.recoveryAuthHash);
  });
});

describe('POST /auth/recovery/rotate (R9)', () => {
  it('replaces the recovery key with the authKey, audits it and keeps every session', async () => {
    const u = await registerViaApi(t.app);
    const other = await newSession(t.app, u);
    const recovery = await createRecoveryBundle(u.bundle.accountKey);
    const res = await request(t.app)
      .post('/api/auth/recovery/rotate')
      .set('Authorization', bearer(u.accessToken))
      .send({
        authKey: u.authKey,
        wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
        recoveryAuthHash: recovery.recoveryAuthHash,
      });
    expect(res.status).toBe(204);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.recoveryAuthHash).toBe(recovery.recoveryAuthHash);
    expect(row.wrappedAccountKeyRecovery).toBe(recovery.wrappedAccountKeyRecovery);
    expect(await actionsOf(u.user.id)).toContain('RECOVERY_KEY_ROTATED');
    expect((await vault(other.accessToken)).status).toBe(200);
    expect((await vault(u.accessToken)).status).toBe(200);

    const oldAuth = b64urlEncode(
      (await deriveRecoveryKeys(parseRecoveryKey(u.bundle.recoveryKey))).authKey,
    );
    const newAuth = b64urlEncode(
      (await deriveRecoveryKeys(parseRecoveryKey(recovery.recoveryKey))).authKey,
    );
    const startWith = (k: string) =>
      request(t.app).post('/api/auth/recovery/start').send({ email: u.email, recoveryAuthKey: k });
    expect((await startWith(oldAuth)).status).toBe(401);
    expect((await startWith(newAuth)).status).toBe(200);
  });

  it('403 with a wrong authKey, 401 without a session', async () => {
    const u = await registerViaApi(t.app);
    const recovery = await createRecoveryBundle(u.bundle.accountKey);
    const body = {
      authKey: TEST_ACCOUNT.authKey,
      wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
      recoveryAuthHash: recovery.recoveryAuthHash,
    };
    const wrong = await request(t.app)
      .post('/api/auth/recovery/rotate')
      .set('Authorization', bearer(u.accessToken))
      .send(body);
    expect(wrong.status).toBe(403);
    expect((await request(t.app).post('/api/auth/recovery/rotate').send(body)).status).toBe(401);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.recoveryAuthHash).toBe(u.bundle.recoveryAuthHash);
  });
});

describe('sessions', () => {
  it('lists active sessions with the current flag, UA summary and IP prefix', async () => {
    const u = await registerViaApi(t.app, { ip: '203.0.113.9' });
    const phone = await newSession(t.app, u, {
      'User-Agent':
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
      'X-Forwarded-For': '2001:db8:abcd:12::1',
    });
    const res = await request(t.app)
      .get('/api/auth/sessions')
      .set('Authorization', bearer(u.accessToken));
    expect(res.status).toBe(200);
    const list = SessionListResponseSchema.parse(res.body);
    expect(list).toHaveLength(2);
    const current = list.filter((s) => s.current);
    expect(current).toHaveLength(1);
    expect(current[0]?.id).toBe(sidOf(u.accessToken));
    expect(current[0]?.ipPrefix).toBe('203.0.113.0/24');
    const other = list.find((s) => s.id === phone.sid);
    expect(other?.ipPrefix).toBe('2001:db8:abcd::/48');
    expect(other?.userAgent).toBeTruthy();
    expect(other?.userAgent).not.toContain('Mozilla');
  });

  it('revokes one session (404 for a session of another user) and audits it', async () => {
    const u = await registerViaApi(t.app);
    const stranger = await registerViaApi(t.app);
    const s = await newSession(t.app, u);
    const foreign = await request(t.app)
      .delete(`/api/auth/sessions/${sidOf(stranger.accessToken)}`)
      .set('Authorization', bearer(u.accessToken));
    expect(foreign.status).toBe(404);
    expect((await vault(stranger.accessToken)).status).toBe(200);

    const del = await request(t.app)
      .delete(`/api/auth/sessions/${s.sid}`)
      .set('Authorization', bearer(u.accessToken));
    expect(del.status).toBe(204);
    const again = await request(t.app)
      .delete(`/api/auth/sessions/${s.sid}`)
      .set('Authorization', bearer(u.accessToken));
    expect(again.status).toBe(404);
    expect(await actionsOf(u.user.id)).toContain('SESSION_REVOKED');
  });

  it('revoke-others keeps only the current session', async () => {
    const u = await registerViaApi(t.app);
    const a = await newSession(t.app, u);
    const b = await newSession(t.app, u);
    const res = await request(t.app)
      .post('/api/auth/sessions/revoke-others')
      .set('Authorization', bearer(u.accessToken));
    expect(res.status).toBe(204);
    for (const s of [a, b]) {
      expect((await vault(s.accessToken)).status).toBe(401);
      expect((await refresh(s.cookie)).status).toBe(401);
    }
    const list = await request(t.app)
      .get('/api/auth/sessions')
      .set('Authorization', bearer(u.accessToken));
    expect(list.body).toHaveLength(1);
    expect(list.body[0].current).toBe(true);
  });
});

describe('POST /auth/refresh after a lost rotation response (grace window)', () => {
  let clock = new Date();
  let g: TestApp;
  let u: RegisteredUser;
  beforeAll(async () => {
    g = await createTestApp({ now: () => clock });
    u = await registerViaApi(g.app);
  });
  afterAll(async () => {
    await g.close();
  });

  const advance = (ms: number) => {
    clock = new Date(clock.getTime() + ms);
  };
  const gRefresh = (cookie: string) =>
    request(g.app).post('/api/auth/refresh').set('Cookie', cookie);
  const reuseEvents = (sid: string) =>
    g.prisma.auditEvent.count({
      where: { action: 'SESSION_REUSE_DETECTED', metadata: { path: ['sessionId'], equals: sid } },
    });
  const liveTokens = (sid: string) =>
    g.prisma.refreshToken.findMany({ where: { sessionId: sid, usedAt: null } });
  const revokedAt = async (sid: string) =>
    (await g.prisma.session.findUniqueOrThrow({ where: { id: sid } })).revokedAt;

  it('a replay inside the window keeps the session: a fresh successor works, the unused one is dead', async () => {
    const s = await newSession(g.app, u);
    const lost = await gRefresh(s.cookie);
    expect(lost.status).toBe(200);
    const unused = cookieFrom(lost);

    advance(5_000);
    const replay = await gRefresh(s.cookie);
    expect(replay.status).toBe(200);
    expect(RefreshResponseSchema.parse(replay.body).user.id).toBe(u.user.id);
    expect(sidOf(replay.body.accessToken as string)).toBe(s.sid);
    const fresh = cookieFrom(replay);
    expect(fresh).not.toBe(unused);
    expect(await liveTokens(s.sid)).toHaveLength(1);

    // The never-delivered successor is dead, and presenting it does not revoke the session.
    expect((await gRefresh(unused)).status).toBe(401);
    expect(await revokedAt(s.sid)).toBeNull();
    expect(await isSidDenylisted(g.redis, s.sid)).toBe(false);
    expect((await gRefresh(fresh)).status).toBe(200);
    expect(await reuseEvents(s.sid)).toBe(0);
  });

  it('every re-issue inside the window revokes the previous unused successor', async () => {
    const s = await newSession(g.app, u);
    const lost = cookieFrom(await gRefresh(s.cookie));
    advance(1_000);
    const second = await gRefresh(s.cookie);
    expect(second.status).toBe(200);
    advance(1_000);
    const third = await gRefresh(s.cookie);
    expect(third.status).toBe(200);
    expect(await liveTokens(s.sid)).toHaveLength(1);
    expect((await gRefresh(lost)).status).toBe(401);
    expect((await gRefresh(cookieFrom(second))).status).toBe(401);
    expect((await gRefresh(cookieFrom(third))).status).toBe(200);
    expect(await revokedAt(s.sid)).toBeNull();
  });

  it('the window is measured from the original rotation and is not extended by re-issues', async () => {
    const s = await newSession(g.app, u);
    expect((await gRefresh(s.cookie)).status).toBe(200);
    advance(REFRESH_GRACE_MS - 1_000);
    const late = await gRefresh(s.cookie);
    expect(late.status).toBe(200);
    advance(2_000);
    expect((await gRefresh(s.cookie)).status).toBe(401);
    expect(await revokedAt(s.sid)).not.toBeNull();
    expect((await gRefresh(cookieFrom(late))).status).toBe(401);
  });

  it('a replay after the window is reuse: the family is revoked', async () => {
    const s = await newSession(g.app, u);
    const first = await gRefresh(s.cookie);
    expect(first.status).toBe(200);
    const child = cookieFrom(first);

    advance(REFRESH_GRACE_MS);
    expect((await gRefresh(s.cookie)).status).toBe(401);
    expect(await revokedAt(s.sid)).not.toBeNull();
    expect(await isSidDenylisted(g.redis, s.sid)).toBe(true);
    expect((await gRefresh(child)).status).toBe(401);
    expect(
      (await request(g.app).get('/api/auth/vault').set('Authorization', bearer(s.accessToken)))
        .status,
    ).toBe(401);
    expect(await reuseEvents(s.sid)).toBe(1);
  });

  it('a replay after the successor was used is reuse, even inside the window', async () => {
    const s = await newSession(g.app, u);
    const first = await gRefresh(s.cookie);
    advance(1_000);
    const second = await gRefresh(cookieFrom(first));
    expect(second.status).toBe(200);

    advance(1_000);
    expect((await gRefresh(s.cookie)).status).toBe(401);
    expect(await revokedAt(s.sid)).not.toBeNull();
    expect(await isSidDenylisted(g.redis, s.sid)).toBe(true);
    expect((await gRefresh(cookieFrom(second))).status).toBe(401);
    expect(await reuseEvents(s.sid)).toBe(1);
  });

  it('concurrent replays never leave two live tokens', async () => {
    const s = await newSession(g.app, u);
    expect((await gRefresh(s.cookie)).status).toBe(200);
    advance(1_000);
    const replays = await Promise.all([1, 2, 3, 4].map(() => gRefresh(s.cookie)));
    const issued = replays.filter((r) => r.status === 200).map((r) => refreshTokenFrom(r));
    expect(issued.length).toBeGreaterThan(0);
    const live = await liveTokens(s.sid);
    expect(live).toHaveLength(1);
    expect(issued.map((tok) => sha256B64url(tok ?? ''))).toContain(live[0]?.tokenHash);
    expect(await revokedAt(s.sid)).toBeNull();
  });

  it('a replay inside the window of a revoked session stays 401', async () => {
    const s = await newSession(g.app, u);
    expect((await gRefresh(s.cookie)).status).toBe(200);
    const del = await request(g.app)
      .delete(`/api/auth/sessions/${s.sid}`)
      .set('Authorization', bearer(u.accessToken));
    expect(del.status).toBe(204);
    advance(1_000);
    expect((await gRefresh(s.cookie)).status).toBe(401);
    expect(await liveTokens(s.sid)).toHaveLength(1);
  });
});
