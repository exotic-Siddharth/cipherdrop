// @vitest-environment node
/**
 * Spec section 7 conformance. The reference below is built only from node:crypto and @node-rs/argon2,
 * and every label is typed from the spec rather than imported from constants.ts: a drift in an HKDF
 * label, salt, nonce layout, AAD or encoding breaks interoperability with existing drops and accounts,
 * and fails here.
 */
import { hashRaw } from '@node-rs/argon2';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes as nodeRandomBytes,
  randomInt,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAccountBundle } from './account';
import type { Argon2Params, KdfParams } from './constants';
import { deriveFileKey, importAesKey } from './keys';
import { decryptManifest, encryptManifest, type Manifest } from './manifest';
import { decryptChunk, encryptChunk } from './stream';
import { createPasswordProtection, unwrapKey, wrapKey } from './wrap';

const EMPTY = Buffer.alloc(0);
const MIN: Argon2Params = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const random = (n: number) => new Uint8Array(nodeRandomBytes(n));
const utf8 = (s: string) => new TextEncoder().encode(s);

const ref = {
  /** HKDF-SHA-256 -> 32 bytes. An AES-256 key derived by WebCrypto deriveKey is the same 32 bytes. */
  hkdf: (ikm: Uint8Array, salt: Uint8Array, info: string) =>
    Buffer.from(hkdfSync('sha256', ikm, salt, info, 32)),
  nonce(i: number, last: boolean) {
    const n = Buffer.alloc(12);
    n.writeUInt32BE(i, 7);
    n[11] = last ? 1 : 0;
    return n;
  },
  seal(key: Uint8Array, iv: Uint8Array, aad: string, pt: Uint8Array) {
    const c = createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(aad, 'utf8'));
    return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  },
  open(key: Uint8Array, iv: Uint8Array, aad: string, sealed: Uint8Array) {
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    return Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
  },
  /** wrap(k, bytes, aad) = b64url(nonce || AES-GCM(k, nonce, aad, bytes)). */
  unwrap(key: Uint8Array, blob: string, aad: string) {
    const raw = Buffer.from(blob, 'base64url');
    return ref.open(key, raw.subarray(0, 12), aad, raw.subarray(12));
  },
  argon2(password: string, kdf: KdfParams) {
    return hashRaw(password.normalize('NFKC'), {
      salt: Buffer.from(kdf.salt, 'base64url'),
      memoryCost: kdf.memoryKiB,
      timeCost: kdf.iterations,
      parallelism: kdf.parallelism,
      outputLen: 32,
    });
  },
  sha256b64url: (b: Uint8Array) => createHash('sha256').update(b).digest('base64url'),
  /** Crockford base32 (8 groups of 4) -> 20 bytes: the digits of a 160-bit big-endian integer. */
  crockford(formatted: string) {
    const digits = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    let n = 0n;
    for (const c of formatted.replaceAll('-', '')) n = n * 32n + BigInt(digits.indexOf(c));
    return Buffer.from(n.toString(16).padStart(40, '0'), 'hex');
  },
};

describe('spec 7.2: per-file keys and the STREAM construction', () => {
  it('matches the pinned golden vector', async () => {
    // DK = 0x00..0x1f, fileId = b64url(0x00..0x0f); expected values computed with node:crypto.
    const dk = Uint8Array.from({ length: 32 }, (_, i) => i);
    const key = await deriveFileKey(dk, 'AAECAwQFBgcICQoLDA0ODw');
    expect(hex(await encryptChunk(key, 0, false, utf8('CipherDrop STREAM vector chunk 0')))).toBe(
      '7a2bffb21b6e88d5a6e2d457ce38238aefc362329834cdc2c9aafb73c9dc83279b5ec3004013bc629a3ade54e191ff7d',
    );
    expect(hex(await encryptChunk(key, 1, true, utf8('chunk 1 (final)')))).toBe(
      'd6286a5c76adba5320f3a1b496766448065ea927777e0c07d51280960b4331',
    );
  });

  it('agrees with the reference for random keys, file ids and positions', async () => {
    for (let round = 0; round < 8; round++) {
      const dk = random(32);
      const fileIdBytes = random(16);
      const fileId = Buffer.from(fileIdBytes).toString('base64url');
      const i = round < 4 ? round : randomInt(0, 2 ** 32 - 1);
      const last = round % 2 === 1;
      const pt = random(randomInt(0, 300));
      const fileKey = ref.hkdf(dk, fileIdBytes, 'cipherdrop/v1/file-key');
      const expected = ref.seal(fileKey, ref.nonce(i, last), 'cipherdrop/v1/chunk', pt);
      const key = await deriveFileKey(dk, fileId);
      expect(hex(await encryptChunk(key, i, last, pt))).toBe(hex(expected));
      expect(hex(await decryptChunk(key, i, last, expected))).toBe(hex(pt));
    }
  });
});

describe('spec 7.3: manifest', () => {
  const manifest: Manifest = {
    v: 1,
    createdAt: 1_762_500_000_000,
    note: 'conformance',
    files: [
      {
        id: 'AAECAwQFBgcICQoLDA0ODw',
        name: 'a.txt',
        size: 3,
        type: 'text/plain',
        lastModified: 1_700_000_000_000,
        chunkSize: 4194304,
        chunkCount: 1,
      },
    ],
  };

  it('encryptManifest = b64url(nonce || AES-GCM(HKDF(DK, empty salt, manifest-key), nonce, aad, JSON))', async () => {
    const dk = random(32);
    const raw = Buffer.from(await encryptManifest(dk, manifest), 'base64url');
    const manifestKey = ref.hkdf(dk, EMPTY, 'cipherdrop/v1/manifest-key');
    const json = ref.open(
      manifestKey,
      raw.subarray(0, 12),
      'cipherdrop/v1/manifest',
      raw.subarray(12),
    );
    expect(JSON.parse(json.toString('utf8'))).toEqual(manifest);
  });

  it('decryptManifest opens a manifest sealed by the reference', async () => {
    const dk = random(32);
    const nonce = random(12);
    const sealed = ref.seal(
      ref.hkdf(dk, EMPTY, 'cipherdrop/v1/manifest-key'),
      nonce,
      'cipherdrop/v1/manifest',
      Buffer.from(JSON.stringify(manifest), 'utf8'),
    );
    const blob = Buffer.concat([nonce, sealed]).toString('base64url');
    expect(await decryptManifest(dk, blob)).toEqual(manifest);
  });
});

describe('spec 7.4: password-protected drops', () => {
  it('kdf, wrappedDropKey, authKey and authKeyHash follow the spec', async () => {
    const dk = random(32);
    // U+FB01 (the "fi" ligature): the reference hashes the NFKC form, "Pass final".
    const password = `Pass ${String.fromCharCode(0xfb01)}nal`;
    const p = await createPasswordProtection(dk, password, MIN);
    expect(Buffer.from(p.kdf.salt, 'base64url')).toHaveLength(16);
    const pk = await ref.argon2(password, p.kdf);
    const wrapKeyBytes = ref.hkdf(pk, EMPTY, 'cipherdrop/v1/drop-password-wrap');
    const authKey = ref.hkdf(pk, EMPTY, 'cipherdrop/v1/drop-password-auth');
    expect(hex(p.authKey)).toBe(hex(authKey));
    expect(p.authKeyHash).toBe(ref.sha256b64url(authKey));
    expect(
      hex(ref.unwrap(wrapKeyBytes, p.wrappedDropKey, 'cipherdrop/v1/wrap/drop-password')),
    ).toBe(hex(dk));
  });
});

describe('spec 7.5: accounts, recovery and owner wrapping', () => {
  it('registration material follows the spec', async () => {
    const password = 'conformance passphrase';
    const bundle = await createAccountBundle(password, MIN);
    const mk = await ref.argon2(password, bundle.kdf);
    expect(hex(bundle.authKey)).toBe(hex(ref.hkdf(mk, EMPTY, 'cipherdrop/v1/account-auth')));
    const encKey = ref.hkdf(mk, EMPTY, 'cipherdrop/v1/account-enc');
    expect(hex(ref.unwrap(encKey, bundle.wrappedAccountKey, 'cipherdrop/v1/wrap/account'))).toBe(
      hex(bundle.accountKey),
    );
    const rk = ref.crockford(bundle.recoveryKey);
    expect(rk).toHaveLength(20);
    const recoveryEnc = ref.hkdf(rk, EMPTY, 'cipherdrop/v1/recovery-enc');
    expect(
      hex(ref.unwrap(recoveryEnc, bundle.wrappedAccountKeyRecovery, 'cipherdrop/v1/wrap/recovery')),
    ).toBe(hex(bundle.accountKey));
    expect(bundle.recoveryAuthHash).toBe(
      ref.sha256b64url(ref.hkdf(rk, EMPTY, 'cipherdrop/v1/recovery-auth')),
    );
  });

  it('ownerWrappedKey = wrap(AK, DK, "cipherdrop/v1/wrap/owner"), both ways', async () => {
    const akRaw = random(32);
    const ak = await importAesKey(akRaw);
    const dk = random(32);
    const ours = await wrapKey(ak, dk, 'cipherdrop/v1/wrap/owner');
    expect(hex(ref.unwrap(akRaw, ours, 'cipherdrop/v1/wrap/owner'))).toBe(hex(dk));
    const nonce = random(12);
    const theirs = Buffer.concat([nonce, ref.seal(akRaw, nonce, 'cipherdrop/v1/wrap/owner', dk)]);
    expect(hex(await unwrapKey(ak, theirs.toString('base64url'), 'cipherdrop/v1/wrap/owner'))).toBe(
      hex(dk),
    );
  });
});
