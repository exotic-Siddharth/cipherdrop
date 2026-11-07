// @vitest-environment node
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAccountBundle, deriveAccountKeys, rewrapForNewPassword } from './account';
import { AAD, type Argon2Params, type KdfParams } from './constants';
import { KdfParamsError, WrongPasswordError } from './errors';
import { deriveRecoveryKeys, parseRecoveryKey } from './recovery';
import { deriveDropPasswordKeys, unwrapKey } from './wrap';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const sha256b64url = (b: Uint8Array) => createHash('sha256').update(b).digest('base64url');
const MIN: Argon2Params = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
const PASSWORD = 'a long and memorable passphrase';

describe('zero-knowledge accounts', () => {
  it('createAccountBundle then deriveAccountKeys(password, kdf) reproduces authKey and unwraps AK', async () => {
    const bundle = await createAccountBundle(PASSWORD, MIN);
    const keys = await deriveAccountKeys(PASSWORD, bundle.kdf);
    expect(hex(keys.authKey)).toBe(hex(bundle.authKey));
    expect(hex(await unwrapKey(keys.encKey, bundle.wrappedAccountKey, AAD.WRAP_ACCOUNT))).toBe(
      hex(bundle.accountKey),
    );
  });

  it('account bundle → login derivation reproduces the same authKey', async () => {
    const bundle = await createAccountBundle(PASSWORD, MIN);
    // Register sends b64url(authKey) and kdf; prelogin later echoes kdf back as JSON.
    const registered = Buffer.from(bundle.authKey).toString('base64url');
    const prelogin = JSON.parse(JSON.stringify({ kdf: bundle.kdf })) as { kdf: KdfParams };
    const login = await deriveAccountKeys(PASSWORD, prelogin.kdf);
    expect(Buffer.from(login.authKey).toString('base64url')).toBe(registered);
  });

  it('a wrong password derives another authKey and cannot unlock the vault', async () => {
    const bundle = await createAccountBundle(PASSWORD, MIN);
    const wrong = await deriveAccountKeys(`${PASSWORD}!`, bundle.kdf);
    expect(hex(wrong.authKey)).not.toBe(hex(bundle.authKey));
    await expect(
      unwrapKey(wrong.encKey, bundle.wrappedAccountKey, AAD.WRAP_ACCOUNT),
    ).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('has the registration wire shape', async () => {
    const bundle = await createAccountBundle(PASSWORD, MIN);
    expect(bundle.kdf).toEqual({
      salt: expect.stringMatching(/^[A-Za-z0-9_-]{21}[AQgw]$/),
      memoryKiB: 19456,
      iterations: 2,
      parallelism: 1,
    });
    expect(bundle.authKey).toHaveLength(32);
    expect(bundle.accountKey).toHaveLength(32);
    expect(bundle.wrappedAccountKey).toMatch(/^[A-Za-z0-9_-]{80}$/);
    expect(bundle.wrappedAccountKeyRecovery).toMatch(/^[A-Za-z0-9_-]{80}$/);
    expect(bundle.recoveryKey).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
    expect(bundle.recoveryAuthHash).toMatch(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
  });

  it("the bundle's recovery key unwraps the same AK", async () => {
    const bundle = await createAccountBundle(PASSWORD, MIN);
    const recovery = await deriveRecoveryKeys(parseRecoveryKey(bundle.recoveryKey));
    expect(sha256b64url(recovery.authKey)).toBe(bundle.recoveryAuthHash);
    const ak = await unwrapKey(
      recovery.encKey,
      bundle.wrappedAccountKeyRecovery,
      AAD.WRAP_RECOVERY,
    );
    expect(hex(ak)).toBe(hex(bundle.accountKey));
  });

  it('every registration draws a fresh salt, AK and recovery key', async () => {
    const a = await createAccountBundle(PASSWORD, MIN);
    const b = await createAccountBundle(PASSWORD, MIN);
    expect(b.kdf.salt).not.toBe(a.kdf.salt);
    expect(hex(b.accountKey)).not.toBe(hex(a.accountKey));
    expect(b.recoveryKey).not.toBe(a.recoveryKey);
  });

  it('defaults to KDF_DEFAULT', async () => {
    const bundle = await createAccountBundle(PASSWORD);
    expect(bundle.kdf).toMatchObject({ memoryKiB: 65536, iterations: 3, parallelism: 1 });
  });

  it('rewrapForNewPassword keeps AK', async () => {
    const bundle = await createAccountBundle('old passphrase', MIN);
    const next = await rewrapForNewPassword(bundle.accountKey, 'new passphrase', MIN);
    expect(next.kdf.salt).not.toBe(bundle.kdf.salt);
    expect(next.wrappedAccountKey).toMatch(/^[A-Za-z0-9_-]{80}$/);
    const keys = await deriveAccountKeys('new passphrase', next.kdf);
    expect(hex(keys.authKey)).toBe(hex(next.authKey));
    expect(hex(await unwrapKey(keys.encKey, next.wrappedAccountKey, AAD.WRAP_ACCOUNT))).toBe(
      hex(bundle.accountKey),
    );
    // The old password opens neither the new wrapping nor yields the new authKey.
    const old = await deriveAccountKeys('old passphrase', next.kdf);
    expect(hex(old.authKey)).not.toBe(hex(next.authKey));
    await expect(
      unwrapKey(old.encKey, next.wrappedAccountKey, AAD.WRAP_ACCOUNT),
    ).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('separates the account and drop-password key domains', async () => {
    const kdf: KdfParams = { salt: 'AAECAwQFBgcICQoLDA0ODw', ...MIN };
    const account = await deriveAccountKeys(PASSWORD, kdf);
    const drop = await deriveDropPasswordKeys(PASSWORD, kdf);
    expect(hex(account.authKey)).not.toBe(hex(drop.authKey));
  });

  it('refuses weak kdf from a downgrading server, and AKs that are not 32 bytes', async () => {
    const downgraded: KdfParams = {
      salt: 'AAECAwQFBgcICQoLDA0ODw',
      memoryKiB: 8192,
      iterations: 1,
      parallelism: 1,
    };
    await expect(deriveAccountKeys(PASSWORD, downgraded)).rejects.toBeInstanceOf(KdfParamsError);
    await expect(rewrapForNewPassword(new Uint8Array(16), PASSWORD, MIN)).rejects.toThrow(
      TypeError,
    );
  });
});
