/**
 * TOTP + backup codes (spec section 10). R23: the next code is generated at Date.now() + 30 s (accepted by the
 * +-1 window) instead of sleeping past the replay guard.
 */
import {
  AAD,
  KDF_MIN,
  b64urlEncode,
  createRecoveryBundle,
  deriveRecoveryKeys,
  parseRecoveryKey,
  rewrapForNewPassword,
  unwrapKey,
} from '@cipherdrop/crypto';
import { AuthSuccessSchema, BackupCodesResponseSchema } from '@cipherdrop/shared';
import { Secret } from 'otpauth';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import {
  bearer,
  enableTotpViaApi,
  loginViaApi,
  newSession,
  refreshTokenFrom,
  registerViaApi,
  sidOf,
  totpCode,
  wrongTotpCode,
} from './testkit';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
});

afterAll(async () => {
  await t.close();
});

const BACKUP_CODE_RE = /^[0-9a-hjkmnp-tv-z]{5}-[0-9a-hjkmnp-tv-z]{5}$/;

const count = (userId: string, action: string) =>
  t.prisma.auditEvent.count({ where: { userId, action: action as never } });

const loginMfa = (mfaToken: string, code: string) =>
  request(t.app).post('/api/auth/login/mfa').send({ mfaToken, code });

async function mfaToken(email: string, password: string): Promise<string> {
  const res = await loginViaApi(t.app, email, password);
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ mfaRequired: true, mfaToken: expect.any(String) });
  expect(refreshTokenFrom(res)).toBeNull();
  return res.body.mfaToken as string;
}

describe('TOTP setup -> enable -> backup codes -> disable', () => {
  it('runs the whole lifecycle', async () => {
    const u = await registerViaApi(t.app);
    const auth = { Authorization: bearer(u.accessToken) };

    const setup = await request(t.app).post('/api/auth/mfa/totp/setup').set(auth);
    expect(setup.status).toBe(200);
    const secret = setup.body.secret as string;
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(Secret.fromBase32(secret).bytes).toHaveLength(20);
    expect(setup.body.otpauthUrl).toMatch(/^otpauth:\/\/totp\/CipherDrop:/);
    expect(setup.body.otpauthUrl).toContain(`secret=${secret}`);
    let row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.totpPendingSecretEnc).toBeTruthy();
    expect(row.totpPendingSecretEnc).not.toContain(secret);
    expect(row.totpEnabledAt).toBeNull();
    expect(row.totpSecretEnc).toBeNull();

    // A wrong code does not enable anything.
    const wrong = await request(t.app)
      .post('/api/auth/mfa/totp/enable')
      .set(auth)
      .send({ authKey: u.authKey, code: wrongTotpCode(secret) });
    expect(wrong.status).toBe(403);
    expect(await count(u.user.id, 'MFA_CHALLENGE_FAILED')).toBe(1);

    const enable = await request(t.app)
      .post('/api/auth/mfa/totp/enable')
      .set(auth)
      .send({ authKey: u.authKey, code: totpCode(secret) });
    expect(enable.status).toBe(200);
    const { backupCodes } = BackupCodesResponseSchema.parse(enable.body);
    expect(new Set(backupCodes).size).toBe(10);
    for (const c of backupCodes) expect(c).toMatch(BACKUP_CODE_RE);
    row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.totpEnabledAt).not.toBeNull();
    expect(row.totpPendingSecretEnc).toBeNull();
    expect(row.totpSecretEnc).not.toContain(secret);
    const stored = await t.prisma.backupCode.findMany({ where: { userId: u.user.id } });
    expect(stored).toHaveLength(10);
    for (const s of stored) {
      for (const c of backupCodes) {
        expect(s.codeHash).not.toContain(c.replace('-', ''));
        expect(s.codeHash.toLowerCase()).not.toContain(c.replace('-', ''));
      }
    }
    expect(await count(u.user.id, 'MFA_ENABLED')).toBe(1);

    // Setup again while enabled: 409.
    expect((await request(t.app).post('/api/auth/mfa/totp/setup').set(auth)).status).toBe(409);
    const refreshed = await request(t.app).post('/api/auth/refresh').set('Cookie', u.cookie);
    expect(refreshed.body.user.totpEnabled).toBe(true);

    // Regenerate with the next step's TOTP code: old backup codes stop working.
    const wrongRegen = await request(t.app)
      .post('/api/auth/mfa/backup-codes')
      .set(auth)
      .send({ authKey: u.authKey, code: wrongTotpCode(secret) });
    expect(wrongRegen.status).toBe(403);
    const regen = await request(t.app)
      .post('/api/auth/mfa/backup-codes')
      .set(auth)
      .send({ authKey: u.authKey, code: totpCode(secret, 30_000) });
    expect(regen.status).toBe(200);
    const fresh = BackupCodesResponseSchema.parse(regen.body).backupCodes;
    expect(fresh.some((c) => backupCodes.includes(c))).toBe(false);
    expect(await count(u.user.id, 'BACKUP_CODES_REGENERATED')).toBe(1);
    const token = await mfaToken(u.email, u.password);
    expect((await loginMfa(token, backupCodes[0] as string)).status).toBe(401);

    // Disable: needs the authKey and a valid code (the TOTP steps are used up here, so a backup code).
    const badDisable = await request(t.app)
      .post('/api/auth/mfa/totp/disable')
      .set(auth)
      .send({ authKey: u.authKey, code: wrongTotpCode(secret) });
    expect(badDisable.status).toBe(403);
    const wrongKey = await request(t.app)
      .post('/api/auth/mfa/totp/disable')
      .set(auth)
      .send({ authKey: Buffer.alloc(32, 5).toString('base64url'), code: fresh[0] });
    expect(wrongKey.status).toBe(403);
    const disable = await request(t.app)
      .post('/api/auth/mfa/totp/disable')
      .set(auth)
      .send({ authKey: u.authKey, code: fresh[1] });
    expect(disable.status).toBe(204);
    row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.totpEnabledAt).toBeNull();
    expect(row.totpSecretEnc).toBeNull();
    expect(row.totpLastStep).toBeNull();
    expect(await t.prisma.backupCode.count({ where: { userId: u.user.id } })).toBe(0);
    expect(await count(u.user.id, 'MFA_DISABLED')).toBe(1);
    expect((await loginViaApi(t.app, u.email, u.password)).body.mfaRequired).toBe(false);
    // Disabling again: 409.
    const again = await request(t.app)
      .post('/api/auth/mfa/totp/disable')
      .set(auth)
      .send({ authKey: u.authKey, code: '123456' });
    expect(again.status).toBe(409);
  });

  it('enabling TOTP signs out every other session (they were opened with the password alone)', async () => {
    const u = await registerViaApi(t.app);
    // Opened before the second factor existed, e.g. by someone who learnt the password.
    const other = await newSession(t.app, u);
    const second = await newSession(t.app, u);
    await enableTotpViaApi(t.app, u);

    // Their access tokens stop at once (denylisted sids), and their refresh cookies are dead.
    for (const s of [other, second]) {
      const vault = await request(t.app)
        .get('/api/auth/vault')
        .set('Authorization', bearer(s.accessToken));
      expect(vault.status).toBe(401);
      expect((await request(t.app).post('/api/auth/refresh').set('Cookie', s.cookie)).status).toBe(
        401,
      );
    }
    // The session that re-authenticated and enrolled stays signed in.
    expect(
      (await request(t.app).get('/api/auth/vault').set('Authorization', bearer(u.accessToken)))
        .status,
    ).toBe(200);
    expect((await request(t.app).post('/api/auth/refresh').set('Cookie', u.cookie)).status).toBe(
      200,
    );
    const live = await t.prisma.session.findMany({
      where: { userId: u.user.id, revokedAt: null },
      select: { id: true },
    });
    expect(live.map((s) => s.id)).toEqual([sidOf(u.accessToken)]);
    const event = await t.prisma.auditEvent.findFirstOrThrow({
      where: { userId: u.user.id, action: 'MFA_ENABLED' },
    });
    expect(event.metadata).toEqual({ revokedSessions: 2 });
  });

  it('an admin cannot turn TOTP off (409), and the refusal spends no code', async () => {
    const u = await registerViaApi(t.app);
    const { backupCodes } = await enableTotpViaApi(t.app, u);
    await t.prisma.user.update({ where: { id: u.user.id }, data: { role: 'ADMIN' } });
    const disable = () =>
      request(t.app)
        .post('/api/auth/mfa/totp/disable')
        .set('Authorization', bearer(u.accessToken))
        .send({ authKey: u.authKey, code: backupCodes[0] });

    const refused = await disable();
    expect(refused.status).toBe(409);
    expect(refused.body.error.message).toMatch(/Admins cannot turn off two-step verification/);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.totpEnabledAt).not.toBeNull();
    expect(row.totpSecretEnc).not.toBeNull();
    expect(await t.prisma.backupCode.count({ where: { userId: u.user.id, usedAt: null } })).toBe(
      10,
    );
    expect(await count(u.user.id, 'MFA_DISABLED')).toBe(0);

    // Demoted, the same (unspent) backup code turns it off.
    await t.prisma.user.update({ where: { id: u.user.id }, data: { role: 'USER' } });
    expect((await disable()).status).toBe(204);
    expect(
      (await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } })).totpEnabledAt,
    ).toBeNull();
  });

  it('enable without a pending setup is a 409', async () => {
    const u = await registerViaApi(t.app);
    const res = await request(t.app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', bearer(u.accessToken))
      .send({ authKey: u.authKey, code: '123456' });
    expect(res.status).toBe(409);
  });
});

describe('login with MFA', () => {
  it('mfaToken -> /login/mfa; wrong code 401 + MFA_CHALLENGE_FAILED; replayed code rejected', async () => {
    const u = await registerViaApi(t.app);
    const { secret } = await enableTotpViaApi(t.app, u);

    const token = await mfaToken(u.email, u.password);
    // An mfaToken is not an access token.
    const asAccess = await request(t.app)
      .get('/api/auth/vault')
      .set('Authorization', bearer(token));
    expect(asAccess.status).toBe(401);

    const failedBefore = await count(u.user.id, 'MFA_CHALLENGE_FAILED');
    const wrong = await loginMfa(token, wrongTotpCode(secret));
    expect(wrong.status).toBe(401);
    expect(wrong.body.error.code).toBe('UNAUTHORIZED');
    expect(await count(u.user.id, 'MFA_CHALLENGE_FAILED')).toBe(failedBefore + 1);

    // The step used to enable TOTP is already consumed: replay.
    expect((await loginMfa(token, totpCode(secret))).status).toBe(401);

    const next = totpCode(secret, 30_000);
    const ok = await loginMfa(token, next);
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    const body = AuthSuccessSchema.parse(ok.body);
    expect(body.user.totpEnabled).toBe(true);
    expect(refreshTokenFrom(ok)).not.toBeNull();
    expect(
      (await request(t.app).get('/api/auth/vault').set('Authorization', bearer(body.accessToken)))
        .status,
    ).toBe(200);
    const success = await t.prisma.auditEvent.findFirst({
      where: { userId: u.user.id, action: 'LOGIN_SUCCESS' },
      orderBy: { createdAt: 'desc' },
    });
    expect(success?.metadata).toEqual({ mfa: 'totp' });

    // The same code again, even with a fresh mfaToken, is a replay.
    const token2 = await mfaToken(u.email, u.password);
    expect((await loginMfa(token2, next)).status).toBe(401);
  });

  it('a backup code works exactly once (case and dash insensitive)', async () => {
    const u = await registerViaApi(t.app);
    const { backupCodes } = await enableTotpViaApi(t.app, u);
    const code = backupCodes[3] as string;
    const typed = code.replace('-', '').toUpperCase();

    const first = await loginMfa(await mfaToken(u.email, u.password), typed);
    expect(first.status).toBe(200);
    expect(await count(u.user.id, 'BACKUP_CODE_USED')).toBe(1);
    const second = await loginMfa(await mfaToken(u.email, u.password), code);
    expect(second.status).toBe(401);
    expect(await t.prisma.backupCode.count({ where: { userId: u.user.id, usedAt: null } })).toBe(9);
    // Another unused code still works.
    expect(
      (await loginMfa(await mfaToken(u.email, u.password), backupCodes[4] as string)).status,
    ).toBe(200);
  });

  it('wrong MFA codes count toward the 10-failure lockout', async () => {
    const u = await registerViaApi(t.app);
    const { secret, backupCodes } = await enableTotpViaApi(t.app, u);
    const token = await mfaToken(u.email, u.password);
    for (let i = 0; i < 10; i++) {
      expect((await loginMfa(token, wrongTotpCode(secret))).status).toBe(401);
    }
    expect(await count(u.user.id, 'LOGIN_LOCKED')).toBe(1);
    // Locked: even a valid backup code and the right authKey are refused, generically.
    expect((await loginMfa(token, backupCodes[0] as string)).status).toBe(401);
    const login = await loginViaApi(t.app, u.email, u.password);
    expect(login.status).toBe(401);
    expect(login.body.error.message).toBe('Invalid email or password');
  });
});

describe('TOTP on recovery and recovery-key rotation', () => {
  it('recovery/complete requires a valid code when TOTP is enabled', async () => {
    const u = await registerViaApi(t.app);
    const { secret } = await enableTotpViaApi(t.app, u);
    const keys = await deriveRecoveryKeys(parseRecoveryKey(u.bundle.recoveryKey));
    const started = await request(t.app)
      .post('/api/auth/recovery/start')
      .send({ email: u.email, recoveryAuthKey: b64urlEncode(keys.authKey) });
    expect(started.status).toBe(200);
    expect(started.body.mfaRequired).toBe(true);
    const ak = await unwrapKey(
      keys.encKey,
      started.body.wrappedAccountKeyRecovery as string,
      AAD.WRAP_RECOVERY,
    );
    const rewrapped = await rewrapForNewPassword(ak, 'a new password 2026', KDF_MIN);
    const recovery = await createRecoveryBundle(ak);
    const body = {
      recoveryToken: started.body.recoveryToken as string,
      newAuthKey: b64urlEncode(rewrapped.authKey),
      kdf: rewrapped.kdf,
      wrappedAccountKey: rewrapped.wrappedAccountKey,
      wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
      recoveryAuthHash: recovery.recoveryAuthHash,
    };
    const complete = (extra: Record<string, string>) =>
      request(t.app)
        .post('/api/auth/recovery/complete')
        .send({ ...body, ...extra });

    expect((await complete({})).status).toBe(401);
    expect((await complete({ code: wrongTotpCode(secret) })).status).toBe(401);
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: u.user.id } });
    expect(row.recoveryAuthHash).toBe(u.bundle.recoveryAuthHash);
    const ok = await complete({ code: totpCode(secret, 30_000) });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(await count(u.user.id, 'RECOVERY_USED')).toBe(1);
  });

  it('recovery/rotate requires a code when TOTP is enabled (400 without, 403 wrong, 204 right)', async () => {
    const u = await registerViaApi(t.app);
    const { secret, backupCodes } = await enableTotpViaApi(t.app, u);
    const recovery = await createRecoveryBundle(u.bundle.accountKey);
    const rotate = (extra: Record<string, string>) =>
      request(t.app)
        .post('/api/auth/recovery/rotate')
        .set('Authorization', bearer(u.accessToken))
        .send({
          authKey: u.authKey,
          wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
          recoveryAuthHash: recovery.recoveryAuthHash,
          ...extra,
        });
    expect((await rotate({})).status).toBe(400);
    expect((await rotate({ code: wrongTotpCode(secret) })).status).toBe(403);
    expect((await rotate({ code: backupCodes[0] as string })).status).toBe(204);
    expect(await count(u.user.id, 'RECOVERY_KEY_ROTATED')).toBe(1);
  });
});
