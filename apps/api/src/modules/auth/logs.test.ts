/** Spec section 12: authKeys, tokens, wrapped keys and codes never reach the logs. */
import { b64urlEncode, deriveRecoveryKeys, parseRecoveryKey } from '@cipherdrop/crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { createLogger } from '../../lib/logger';
import {
  bearer,
  enableTotpViaApi,
  loginViaApi,
  refreshTokenFrom,
  registerViaApi,
  totpCode,
} from './testkit';

const lines: string[] = [];
let t: TestApp;

beforeAll(async () => {
  t = await createTestApp({
    logger: createLogger({ level: 'trace', destination: { write: (s: string) => lines.push(s) } }),
  });
});

afterAll(async () => {
  await t.close();
});

describe('logging', () => {
  it('no authKey, token, wrapped key, recovery key, TOTP secret or code appears in the pino output', async () => {
    const u = await registerViaApi(t.app);
    const secrets: string[] = [
      u.authKey,
      u.accessToken,
      u.cookie.split('=')[1] as string,
      u.bundle.wrappedAccountKey,
      u.bundle.wrappedAccountKeyRecovery,
      u.bundle.recoveryAuthHash,
      u.email,
    ];

    const login = await loginViaApi(t.app, u.email, u.password);
    secrets.push(login.body.accessToken as string, refreshTokenFrom(login) as string);
    // Failures and validation errors are logged too: make sure they do not leak either.
    await request(t.app)
      .post('/api/auth/login')
      .send({ email: u.email, authKey: u.authKey.slice(0, 40) });
    await request(t.app)
      .post('/api/auth/login')
      .send({ email: u.email, authKey: Buffer.alloc(32, 9).toString('base64url') });
    const rk = await deriveRecoveryKeys(parseRecoveryKey(u.bundle.recoveryKey));
    const recoveryAuthKey = b64urlEncode(rk.authKey);
    secrets.push(recoveryAuthKey, u.bundle.recoveryKey);
    const started = await request(t.app)
      .post('/api/auth/recovery/start')
      .send({ email: u.email, recoveryAuthKey });
    secrets.push(started.body.recoveryToken as string);

    const { secret, backupCodes } = await enableTotpViaApi(t.app, u.accessToken);
    secrets.push(secret, ...backupCodes);
    const mfa = await loginViaApi(t.app, u.email, u.password);
    secrets.push(mfa.body.mfaToken as string);
    const code = totpCode(secret, 30_000);
    const done = await request(t.app)
      .post('/api/auth/login/mfa')
      .send({ mfaToken: mfa.body.mfaToken, code });
    expect(done.status).toBe(200);
    secrets.push(done.body.accessToken as string);
    await request(t.app).get('/api/auth/vault').set('Authorization', bearer(u.accessToken));

    const output = lines.join('');
    expect(output).toContain('/api/auth/login');
    for (const s of secrets) {
      expect(s.length).toBeGreaterThan(5);
      expect(output.includes(s), `log output contains a secret (${s.slice(0, 4)}...)`).toBe(false);
    }
    expect(output).not.toMatch(/"(authKey|code|cookie|authorization)"\s*:\s*"[^[]/i);
  });
});
