// @vitest-environment node
import { hash, hashRaw } from '@node-rs/argon2';
import { describe, expect, it } from 'vitest';
import type { Argon2Params } from './constants';
import { KdfParamsError } from './errors';
import { argon2id, assertKdfParams } from './kdf';

const ascii = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const SALT16 = Uint8Array.from({ length: 16 }, (_, i) => i);
/** U+FB01 LATIN SMALL LIGATURE FI: NFKC maps it to "fi". */
const FI_LIGATURE = String.fromCharCode(0xfb01);
/** U+0301 COMBINING ACUTE ACCENT: NFKC composes "e" + U+0301 into "é". */
const COMBINING_ACUTE = String.fromCharCode(0x0301);
/** Spec 7.1 bounds, typed here from the spec rather than imported. */
const MIN: Argon2Params = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
const DEFAULT: Argon2Params = { memoryKiB: 65536, iterations: 3, parallelism: 1 };
const MAX: Argon2Params = { memoryKiB: 262144, iterations: 10, parallelism: 4 };

/** The independent oracle (R20): @node-rs/argon2 (Rust `argon2` crate). Its defaults are Argon2id v1.3. */
async function oracle(password: string, salt: Uint8Array, p: Argon2Params): Promise<string> {
  const out = await hashRaw(password, {
    salt,
    memoryCost: p.memoryKiB,
    timeCost: p.iterations,
    parallelism: p.parallelism,
    outputLen: 32,
  });
  return out.toString('hex');
}

describe('argon2id regression vectors (R20)', () => {
  // Published known-answer tests of the Argon2 reference implementation (phc-winner-argon2, src/test.c):
  // Argon2id v1.3, password "password", salt "somesalt", 32-byte tag. Both lie within [KDF_MIN, KDF_MAX].
  it.each([
    {
      m: 65536,
      t: 2,
      p: 1,
      tag: '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
    },
    {
      m: 262144,
      t: 2,
      p: 1,
      tag: '78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c',
    },
  ])('reproduces the reference KAT m=$m t=$t p=$p (and so does the oracle)', async (v) => {
    const params = { memoryKiB: v.m, iterations: v.t, parallelism: v.p };
    expect(hex(await argon2id('password', ascii('somesalt'), params))).toBe(v.tag);
    expect(await oracle('password', ascii('somesalt'), params)).toBe(v.tag);
  });

  it('the oracle really computes Argon2id v1.3 with these options', async () => {
    const phc = await hash('password', {
      salt: ascii('somesalt'),
      memoryCost: 65536,
      timeCost: 2,
      parallelism: 1,
      outputLen: 32,
    });
    expect(phc).toBe(
      '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc',
    );
  });

  it.each([
    { name: 'KDF_MIN', params: MIN },
    { name: 'parallelism 2', params: { memoryKiB: 24576, iterations: 3, parallelism: 2 } },
    { name: 'KDF_MAX', params: MAX },
  ])('matches @node-rs/argon2 hashRaw at $name', async ({ params }) => {
    // Decomposed "é" and the "ﬁ" ligature: the oracle receives the NFKC form the spec mandates.
    const password = `Passwe${COMBINING_ACUTE}rd ${FI_LIGATURE} ✓`;
    expect(hex(await argon2id(password, SALT16, params))).toBe(
      await oracle(password.normalize('NFKC'), SALT16, params),
    );
  });
});

describe('argon2id', () => {
  it('NFKC: "ﬁ" and "fi" derive identical keys', async () => {
    const ligature = await argon2id(FI_LIGATURE, SALT16, MIN);
    const plain = await argon2id('fi', SALT16, MIN);
    expect(hex(ligature)).toBe(hex(plain));
    expect(ligature).toHaveLength(32);
  });

  it('refuses parameters outside the bounds before doing any work', async () => {
    const weak = { memoryKiB: 1024, iterations: 1, parallelism: 1 };
    await expect(argon2id('password', SALT16, weak)).rejects.toBeInstanceOf(KdfParamsError);
  });

  it('refuses salts shorter than the Argon2 minimum of 8 bytes', async () => {
    await expect(argon2id('password', new Uint8Array(7), MIN)).rejects.toBeInstanceOf(
      KdfParamsError,
    );
  });

  it('refuses an empty password and a non-string password', async () => {
    await expect(argon2id('', SALT16, MIN)).rejects.toThrow(TypeError);
    await expect(argon2id(undefined as unknown as string, SALT16, MIN)).rejects.toThrow(TypeError);
  });
});

describe('assertKdfParams', () => {
  it('accepts the default and every corner of the allowed box', () => {
    const accepted: Argon2Params[] = [
      MIN,
      DEFAULT,
      MAX,
      { memoryKiB: 19456, iterations: 10, parallelism: 4 },
      { memoryKiB: 262144, iterations: 2, parallelism: 1 },
    ];
    for (const p of accepted) expect(() => assertKdfParams(p), JSON.stringify(p)).not.toThrow();
  });

  it.each([
    ['memory one KiB below KDF_MIN', { memoryKiB: 19455, iterations: 2, parallelism: 1 }],
    ['iterations below KDF_MIN', { memoryKiB: 65536, iterations: 1, parallelism: 1 }],
    ['parallelism 0', { memoryKiB: 65536, iterations: 3, parallelism: 0 }],
    ['a classic weak 4 MiB, t=1 downgrade', { memoryKiB: 4096, iterations: 1, parallelism: 1 }],
  ])('rejects weak params: %s', (_, p) => {
    expect(() => assertKdfParams(p)).toThrow(KdfParamsError);
  });

  it.each([
    ['memory one KiB above KDF_MAX', { memoryKiB: 262145, iterations: 3, parallelism: 1 }],
    ['iterations above KDF_MAX', { memoryKiB: 65536, iterations: 11, parallelism: 1 }],
    ['parallelism above KDF_MAX', { memoryKiB: 65536, iterations: 3, parallelism: 5 }],
    ['4 GiB of memory', { memoryKiB: 4194304, iterations: 3, parallelism: 1 }],
  ])('rejects absurd params: %s', (_, p) => {
    expect(() => assertKdfParams(p)).toThrow(KdfParamsError);
  });

  it.each([
    ['a fractional value', { memoryKiB: 65536.5, iterations: 3, parallelism: 1 }],
    ['NaN', { memoryKiB: Number.NaN, iterations: 3, parallelism: 1 }],
    ['a numeric string', { memoryKiB: '65536', iterations: 3, parallelism: 1 }],
    ['a missing field', { memoryKiB: 65536, iterations: 3 }],
    ['null', null],
  ])('rejects malformed params: %s', (_, p) => {
    expect(() => assertKdfParams(p as unknown as Argon2Params)).toThrow(KdfParamsError);
  });
});
