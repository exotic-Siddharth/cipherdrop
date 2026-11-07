// @vitest-environment node
import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AAD, type Argon2Params, type KdfParams } from './constants';
import { CryptoError, IntegrityError, KdfParamsError, WrongPasswordError } from './errors';
import { generateDropKey, importAesKey } from './keys';
import { createPasswordProtection, deriveDropPasswordKeys, unwrapKey, wrapKey } from './wrap';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const random = (n: number) => new Uint8Array(nodeRandomBytes(n));
const sha256b64url = (b: Uint8Array) => createHash('sha256').update(b).digest('base64url');
const WRAPPED_RE = /^[A-Za-z0-9_-]{80}$/;
const SALT_RE = /^[A-Za-z0-9_-]{21}[AQgw]$/;
/** Spec 7.1 KDF_MIN, typed here from the spec: fast enough for unit tests. */
const MIN: Argon2Params = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
const PASSWORD = 'correct horse battery staple';

describe('wrapKey / unwrapKey', () => {
  it('roundtrips a 32-byte key as exactly 80 b64url chars', async () => {
    const k = await importAesKey(random(32));
    const dk = generateDropKey();
    const blob = await wrapKey(k, dk, AAD.WRAP_OWNER);
    expect(blob).toMatch(WRAPPED_RE);
    expect(Buffer.from(blob, 'base64url')).toHaveLength(12 + 32 + 16);
    expect(hex(await unwrapKey(k, blob, AAD.WRAP_OWNER))).toBe(hex(dk));
  });

  it('uses a fresh nonce for every wrap', async () => {
    const k = await importAesKey(random(32));
    const dk = generateDropKey();
    const a = await wrapKey(k, dk, AAD.WRAP_OWNER);
    const b = await wrapKey(k, dk, AAD.WRAP_OWNER);
    expect(a.slice(0, 16)).not.toBe(b.slice(0, 16));
  });

  it('wrong AAD fails', async () => {
    const k = await importAesKey(random(32));
    const blob = await wrapKey(k, generateDropKey(), AAD.WRAP_OWNER);
    for (const aad of [AAD.WRAP_ACCOUNT, AAD.WRAP_RECOVERY, AAD.WRAP_DROP_PASSWORD]) {
      await expect(unwrapKey(k, blob, aad), aad).rejects.toBeInstanceOf(CryptoError);
    }
  });

  it('the wrong key or a flipped bit fails', async () => {
    const k = await importAesKey(random(32));
    const blob = await wrapKey(k, generateDropKey(), AAD.WRAP_OWNER);
    const other = await importAesKey(random(32));
    await expect(unwrapKey(other, blob, AAD.WRAP_OWNER)).rejects.toBeInstanceOf(IntegrityError);
    const raw = Buffer.from(blob, 'base64url');
    raw[40] ^= 0x01;
    await expect(unwrapKey(k, raw.toString('base64url'), AAD.WRAP_OWNER)).rejects.toBeInstanceOf(
      IntegrityError,
    );
  });

  it('a failed unwrap under a password or recovery label is WrongPasswordError', async () => {
    const blob = await wrapKey(await importAesKey(random(32)), generateDropKey(), AAD.WRAP_ACCOUNT);
    const guess = await importAesKey(random(32));
    for (const aad of [AAD.WRAP_ACCOUNT, AAD.WRAP_DROP_PASSWORD, AAD.WRAP_RECOVERY]) {
      await expect(unwrapKey(guess, blob, aad), aad).rejects.toBeInstanceOf(WrongPasswordError);
    }
  });

  it('a malformed blob is an IntegrityError, whatever the label', async () => {
    const k = await importAesKey(random(32));
    const good = await wrapKey(k, generateDropKey(), AAD.WRAP_ACCOUNT);
    for (const blob of ['', good.slice(0, 79), `${good}AAAA`, `${good.slice(0, 79)}+`]) {
      await expect(unwrapKey(k, blob, AAD.WRAP_ACCOUNT), blob).rejects.toBeInstanceOf(
        IntegrityError,
      );
    }
  });

  it('wraps only 32-byte keys, and only under the four wrap labels', async () => {
    const k = await importAesKey(random(32));
    const blob = await wrapKey(k, generateDropKey(), AAD.WRAP_OWNER);
    await expect(wrapKey(k, random(16), AAD.WRAP_OWNER)).rejects.toThrow(TypeError);
    await expect(wrapKey(k, generateDropKey(), AAD.CHUNK)).rejects.toThrow(TypeError);
    await expect(wrapKey(k, generateDropKey(), 'cipherdrop/v1/wrap/other')).rejects.toThrow(
      TypeError,
    );
    await expect(unwrapKey(k, blob, AAD.MANIFEST)).rejects.toThrow(TypeError);
  });
});

describe('password-protected drops', () => {
  it('password wrap/unwrap', async () => {
    const dk = generateDropKey();
    const p = await createPasswordProtection(dk, PASSWORD, MIN);
    expect(p.kdf).toEqual({
      salt: expect.stringMatching(SALT_RE),
      memoryKiB: 19456,
      iterations: 2,
      parallelism: 1,
    });
    expect(p.wrappedDropKey).toMatch(WRAPPED_RE);
    expect(p.authKey).toHaveLength(32);
    expect(p.authKeyHash).toBe(sha256b64url(p.authKey));
    // The recipient re-derives both keys from the password and the kdf the server stored.
    const keys = await deriveDropPasswordKeys(PASSWORD, p.kdf);
    expect(hex(keys.authKey)).toBe(hex(p.authKey));
    expect(hex(await unwrapKey(keys.wrapKey, p.wrappedDropKey, AAD.WRAP_DROP_PASSWORD))).toBe(
      hex(dk),
    );
  });

  it('wrong-password failure', async () => {
    const p = await createPasswordProtection(generateDropKey(), PASSWORD, MIN);
    const keys = await deriveDropPasswordKeys('Correct horse battery staple', p.kdf);
    // The server's constant-time compare refuses /unlock...
    expect(sha256b64url(keys.authKey)).not.toBe(p.authKeyHash);
    // ...and even a released wrappedDropKey does not open.
    await expect(
      unwrapKey(keys.wrapKey, p.wrappedDropKey, AAD.WRAP_DROP_PASSWORD),
    ).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('defaults to KDF_DEFAULT and draws a fresh salt for every drop', async () => {
    const dk = generateDropKey();
    const a = await createPasswordProtection(dk, PASSWORD);
    expect(a.kdf).toMatchObject({ memoryKiB: 65536, iterations: 3, parallelism: 1 });
    const b = await createPasswordProtection(dk, PASSWORD, MIN);
    expect(b.kdf.salt).not.toBe(a.kdf.salt);
    expect(b.authKeyHash).not.toBe(a.authKeyHash);
  });

  it('copies only the cost parameters, never a salt passed in with them', async () => {
    const reused = { ...MIN, salt: 'AAAAAAAAAAAAAAAAAAAAAA' } as Argon2Params;
    const p = await createPasswordProtection(generateDropKey(), PASSWORD, reused);
    expect(p.kdf.salt).not.toBe('AAAAAAAAAAAAAAAAAAAAAA');
    expect(Object.keys(p.kdf).sort()).toEqual(['iterations', 'memoryKiB', 'parallelism', 'salt']);
  });

  it('refuses weak parameters from the sender and from a downgrading server', async () => {
    const weak = { memoryKiB: 4096, iterations: 1, parallelism: 1 };
    await expect(
      createPasswordProtection(generateDropKey(), PASSWORD, weak),
    ).rejects.toBeInstanceOf(KdfParamsError);
    const downgraded: KdfParams = { salt: 'AAECAwQFBgcICQoLDA0ODw', ...weak };
    await expect(deriveDropPasswordKeys(PASSWORD, downgraded)).rejects.toBeInstanceOf(
      KdfParamsError,
    );
  });

  it('refuses a kdf salt that is not the canonical b64url of 16 bytes', async () => {
    for (const salt of [
      '',
      'AAECAwQFBgcICQoL',
      `${'A'.repeat(21)}B`,
      'A'.repeat(23),
      '+'.repeat(22),
    ]) {
      const kdf: KdfParams = { ...MIN, salt };
      await expect(deriveDropPasswordKeys(PASSWORD, kdf), salt).rejects.toBeInstanceOf(
        KdfParamsError,
      );
    }
  });

  it('refuses an empty password and a drop key that is not 32 bytes', async () => {
    await expect(createPasswordProtection(generateDropKey(), '', MIN)).rejects.toThrow(TypeError);
    await expect(createPasswordProtection(random(16), PASSWORD, MIN)).rejects.toThrow(TypeError);
  });
});
