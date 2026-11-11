// @vitest-environment node
import {
  AAD,
  b64urlEncode,
  createAccountBundle,
  deriveAccountKeys,
  deriveRecoveryKeys,
  importAesKey,
  KDF_MIN,
  parseRecoveryKey,
  unwrapKey,
  wrapKey,
} from '@cipherdrop/crypto';
import { describe, expect, it } from 'vitest';
import { handleKdfRequest, serializeKdfError } from './kdf.worker';

const PASSWORD = 'correct horse battery staple';

describe('kdf.worker logic', () => {
  it('unlockVault returns a non-extractable AK that opens what the original AK wrapped', async () => {
    const bundle = await createAccountBundle(PASSWORD, KDF_MIN);
    const res = await handleKdfRequest({
      op: 'unlockVault',
      password: PASSWORD,
      kdf: bundle.kdf,
      wrappedAccountKey: bundle.wrappedAccountKey,
    });
    expect(res.accountKey.extractable).toBe(false);
    const original = await importAesKey(bundle.accountKey);
    const dk = new Uint8Array(32).fill(7);
    const wrapped = await wrapKey(original, dk, AAD.WRAP_OWNER);
    expect(await unwrapKey(res.accountKey, wrapped, AAD.WRAP_OWNER)).toEqual(dk);
    expect(res.authKey).toBe(b64urlEncode(bundle.authKey));
  });

  it('unlockVault with a wrong password fails with a WRONG_PASSWORD code', async () => {
    const bundle = await createAccountBundle(PASSWORD, KDF_MIN);
    const err = await handleKdfRequest({
      op: 'unlockVault',
      password: 'not the password',
      kdf: bundle.kdf,
      wrappedAccountKey: bundle.wrappedAccountKey,
    }).catch((e: unknown) => e);
    expect(serializeKdfError(err)).toMatchObject({ code: 'WRONG_PASSWORD' });
  });

  it('changePassword re-wraps the same AK under the new password', async () => {
    const bundle = await createAccountBundle(PASSWORD, KDF_MIN);
    const res = await handleKdfRequest({
      op: 'changePassword',
      currentPassword: PASSWORD,
      kdf: bundle.kdf,
      wrappedAccountKey: bundle.wrappedAccountKey,
      newPassword: 'a brand new passphrase 42',
      params: KDF_MIN,
    });
    expect(res.currentAuthKey).toBe(b64urlEncode(bundle.authKey));
    const { encKey } = await deriveAccountKeys('a brand new passphrase 42', res.kdf);
    const ak = await unwrapKey(encKey, res.wrappedAccountKey, AAD.WRAP_ACCOUNT);
    expect(ak).toEqual(bundle.accountKey);
    expect(res.newAuthKey).not.toBe(res.currentAuthKey);
  });

  it('rotateRecoveryKey returns a fresh recovery key that unwraps the same AK', async () => {
    const bundle = await createAccountBundle(PASSWORD, KDF_MIN);
    const res = await handleKdfRequest({
      op: 'rotateRecoveryKey',
      password: PASSWORD,
      kdf: bundle.kdf,
      wrappedAccountKey: bundle.wrappedAccountKey,
    });
    expect(res.recoveryKey).not.toBe(bundle.recoveryKey);
    const { encKey } = await deriveRecoveryKeys(parseRecoveryKey(res.recoveryKey));
    expect(await unwrapKey(encKey, res.wrappedAccountKeyRecovery, AAD.WRAP_RECOVERY)).toEqual(
      bundle.accountKey,
    );
  });

  it('completeRecovery unwraps with the recovery key, sets a new password and rotates the recovery key', async () => {
    const bundle = await createAccountBundle(PASSWORD, KDF_MIN);
    const start = await handleKdfRequest({
      op: 'deriveRecoveryAuth',
      recoveryKey: bundle.recoveryKey.toLowerCase(),
    });
    expect(typeof start.recoveryAuthKey).toBe('string');
    const res = await handleKdfRequest({
      op: 'completeRecovery',
      recoveryKey: bundle.recoveryKey,
      wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
      newPassword: 'another passphrase 1234',
      params: KDF_MIN,
    });
    const { encKey } = await deriveAccountKeys('another passphrase 1234', res.kdf);
    expect(await unwrapKey(encKey, res.wrappedAccountKey, AAD.WRAP_ACCOUNT)).toEqual(
      bundle.accountKey,
    );
    expect(res.newRecoveryKey).not.toBe(bundle.recoveryKey);
    expect(res.accountKey.extractable).toBe(false);
  });

  it('serializeKdfError keeps the crypto code and maps misuse to TYPE_ERROR', () => {
    expect(serializeKdfError(new TypeError('bad'))).toEqual({ code: 'TYPE_ERROR', message: 'bad' });
    expect(serializeKdfError('weird')).toMatchObject({ code: 'UNKNOWN' });
  });
});
