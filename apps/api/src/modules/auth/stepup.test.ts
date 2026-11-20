/**
 * Step-up on every sensitive signed-in route (review server-3): one rule, requireAccountProof. The current
 * authKey, plus a TOTP or backup code when TOTP is on (a TOTP code only where a backup code would mint new
 * ones). A stolen access token alone can do none of these, and a refused attempt changes nothing.
 */
import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import {
  bearer,
  enableTotpViaApi,
  newSession,
  registerViaApi,
  totpCode,
  wrongTotpCode,
  type RegisteredUser,
} from './testkit';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
});

afterAll(async () => {
  await t.close();
});

const WRONG_AUTH_KEY = Buffer.alloc(32, 0xa5).toString('base64url');
const key32 = () => randomBytes(32).toString('base64url');

interface Proof {
  authKey: string;
  code?: string;
}

interface SensitiveRoute {
  name: string;
  /** Status of a successful call. */
  ok: number;
  /** Only a TOTP code is accepted as the second factor (a backup code would mint new backup codes). */
  totpOnly?: boolean;
  send: (u: RegisteredUser, proof: Proof, extra: { otherSid: string }) => request.Test;
}

const withAuth = (u: RegisteredUser, test: request.Test) =>
  test.set('Authorization', bearer(u.accessToken));

/** Every sensitive signed-in route (with TOTP on). TOTP enable is checked separately: TOTP is off there. */
const ROUTES: SensitiveRoute[] = [
  {
    name: 'POST /auth/password',
    ok: 204,
    send: (u, proof) =>
      withAuth(u, request(t.app).post('/api/auth/password')).send({
        currentAuthKey: proof.authKey,
        ...(proof.code ? { code: proof.code } : {}),
        newAuthKey: key32(),
        kdf: u.bundle.kdf,
        wrappedAccountKey: u.bundle.wrappedAccountKey,
      }),
  },
  {
    name: 'POST /auth/recovery/rotate',
    ok: 204,
    send: (u, proof) =>
      withAuth(u, request(t.app).post('/api/auth/recovery/rotate')).send({
        ...proof,
        wrappedAccountKeyRecovery: u.bundle.wrappedAccountKeyRecovery,
        recoveryAuthHash: key32(),
      }),
  },
  {
    name: 'POST /auth/mfa/totp/disable',
    ok: 204,
    send: (u, proof) => withAuth(u, request(t.app).post('/api/auth/mfa/totp/disable')).send(proof),
  },
  {
    name: 'POST /auth/mfa/backup-codes',
    ok: 200,
    totpOnly: true,
    send: (u, proof) => withAuth(u, request(t.app).post('/api/auth/mfa/backup-codes')).send(proof),
  },
  {
    name: 'DELETE /auth/sessions/:id',
    ok: 204,
    send: (u, proof, { otherSid }) =>
      withAuth(u, request(t.app).delete(`/api/auth/sessions/${otherSid}`)).send(proof),
  },
  {
    name: 'POST /auth/sessions/revoke-others',
    ok: 204,
    send: (u, proof) =>
      withAuth(u, request(t.app).post('/api/auth/sessions/revoke-others')).send(proof),
  },
  {
    name: 'DELETE /me',
    ok: 204,
    send: (u, proof) => withAuth(u, request(t.app).delete('/api/me')).send(proof),
  },
];

/** What a refused attempt must leave untouched. */
async function snapshot(userId: string) {
  const user = await t.prisma.user.findUnique({ where: { id: userId } });
  return {
    authKeyHash: user?.authKeyHash,
    recoveryAuthHash: user?.recoveryAuthHash,
    totpEnabledAt: user?.totpEnabledAt?.toISOString(),
    totpSecretEnc: user?.totpSecretEnc,
    backupCodes: (await t.prisma.backupCode.findMany({ where: { userId } }))
      .map((c) => `${c.codeHash}:${c.usedAt?.toISOString() ?? '-'}`)
      .sort(),
    liveSessions: await t.prisma.session.count({ where: { userId, revokedAt: null } }),
  };
}

const challengeFailures = (userId: string) =>
  t.prisma.auditEvent.count({ where: { userId, action: 'MFA_CHALLENGE_FAILED' } });

describe('every sensitive route needs the authKey and, with TOTP on, a second factor', () => {
  it.each(ROUTES.map((r) => [r.name, r] as const))('%s', async (_name, route) => {
    const u = await registerViaApi(t.app);
    const other = await newSession(t.app, u); // before TOTP is on, while a password login suffices
    const { secret, backupCodes } = await enableTotpViaApi(t.app, u);
    const extra = { otherSid: other.sid };
    const goodCode = route.totpOnly ? totpCode(secret, 30_000) : (backupCodes[0] as string);
    const before = await snapshot(u.user.id);

    // A stolen access token without the password: refused, whatever the code.
    const noPassword = await route.send(u, { authKey: WRONG_AUTH_KEY, code: goodCode }, extra);
    expect(noPassword.status, JSON.stringify(noPassword.body)).toBe(403);
    expect(noPassword.body.error).toMatchObject({
      code: 'FORBIDDEN',
      message: 'Incorrect password',
    });

    // The password without the second factor: refused.
    const noCode = await route.send(u, { authKey: u.authKey }, extra);
    expect(noCode.status, JSON.stringify(noCode.body)).toBe(400);
    expect(noCode.body.error.code).toBe('VALIDATION_ERROR');

    // The password with a wrong code: refused and audited.
    const failures = await challengeFailures(u.user.id);
    const wrongCode = await route.send(
      u,
      { authKey: u.authKey, code: wrongTotpCode(secret) },
      extra,
    );
    expect(wrongCode.status, JSON.stringify(wrongCode.body)).toBe(403);
    expect(wrongCode.body.error.message).toBe('Invalid two-factor code');
    expect(await challengeFailures(u.user.id)).toBe(failures + 1);

    if (route.totpOnly) {
      // A backup code cannot stand in for the authenticator here (it would mint ten new ones).
      const backup = await route.send(
        u,
        { authKey: u.authKey, code: backupCodes[0] as string },
        extra,
      );
      expect(backup.status, JSON.stringify(backup.body)).toBe(400);
    }

    expect(await snapshot(u.user.id)).toEqual(before);
    expect((await route.send(u, { authKey: u.authKey, code: goodCode }, extra)).status).toBe(
      route.ok,
    );
  });

  it('without TOTP the authKey alone is enough, and still required', async () => {
    for (const route of ROUTES.filter((r) => !r.name.includes('/mfa/'))) {
      const u = await registerViaApi(t.app);
      const other = await newSession(t.app, u);
      const extra = { otherSid: other.sid };
      const before = await snapshot(u.user.id);
      const refused = await route.send(u, { authKey: WRONG_AUTH_KEY }, extra);
      expect(refused.status, route.name).toBe(403);
      expect(await snapshot(u.user.id)).toEqual(before);
      expect((await route.send(u, { authKey: u.authKey }, extra)).status, route.name).toBe(
        route.ok,
      );
    }
  });

  it('POST /auth/mfa/totp/enable needs the authKey too (a token thief cannot enrol their own authenticator)', async () => {
    const u = await registerViaApi(t.app);
    const setup = await withAuth(u, request(t.app).post('/api/auth/mfa/totp/setup'));
    expect(setup.status).toBe(200);
    const secret = setup.body.secret as string;
    const enable = (body: object) =>
      withAuth(u, request(t.app).post('/api/auth/mfa/totp/enable')).send(body);

    expect((await enable({ code: totpCode(secret) })).status).toBe(400);
    const stolen = await enable({ authKey: WRONG_AUTH_KEY, code: totpCode(secret) });
    expect(stolen.status).toBe(403);
    expect(stolen.body.error.message).toBe('Incorrect password');
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.totpEnabledAt).toBeNull();
    expect(row.totpSecretEnc).toBeNull();
    expect(await t.prisma.backupCode.count({ where: { userId: u.user.id } })).toBe(0);

    const ok = await enable({ authKey: u.authKey, code: totpCode(secret) });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.backupCodes).toHaveLength(10);
  });
});
