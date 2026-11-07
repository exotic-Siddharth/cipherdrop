// @vitest-environment node
import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AAD } from './constants';
import { WrongPasswordError } from './errors';
import {
  createRecoveryBundle,
  deriveRecoveryKeys,
  generateRecoveryKey,
  parseRecoveryKey,
} from './recovery';
import { unwrapKey } from './wrap';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const random = (n: number) => new Uint8Array(nodeRandomBytes(n));
const chars = (...codes: number[]) => String.fromCharCode(...codes);
const FORMAT = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/;

/** Independent reference: the 160-bit big-endian integer written as 32 Crockford base-32 digits. */
function referenceFormat(raw: Uint8Array): string {
  const digits = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let n = BigInt(`0x${hex(raw)}`);
  let out = '';
  for (let i = 0; i < 32; i++) {
    out = digits[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return out.match(/.{4}/g)!.join('-');
}

/** The whole alphabet in order is a valid key: hex computed independently with BigInt. */
const ALPHABET_KEY = '0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
const ALPHABET_KEY_HEX = '00443214c74254b635cf84653a56d7c675be77df';

describe('recovery keys', () => {
  it('are 20 random bytes shown as 8 groups of 4 Crockford base32 characters', () => {
    for (let i = 0; i < 20; i++) {
      const rk = generateRecoveryKey();
      expect(rk.raw).toHaveLength(20);
      expect(rk.formatted).toMatch(FORMAT);
      expect(rk.formatted).toBe(referenceFormat(rk.raw));
    }
    expect(generateRecoveryKey().formatted).not.toBe(generateRecoveryKey().formatted);
  });

  it('format/parse roundtrip', () => {
    for (let i = 0; i < 20; i++) {
      const rk = generateRecoveryKey();
      expect(hex(parseRecoveryKey(rk.formatted))).toBe(hex(rk.raw));
    }
  });

  it('parses known vectors', () => {
    expect(hex(parseRecoveryKey(ALPHABET_KEY))).toBe(ALPHABET_KEY_HEX);
    expect(hex(parseRecoveryKey('000G-40R4-0M30-E209-185G-R38E-1W81-24GK'))).toBe(
      '000102030405060708090a0b0c0d0e0f10111213',
    );
    expect(hex(parseRecoveryKey('0000-0000-0000-0000-0000-0000-0000-0000'))).toBe('00'.repeat(20));
    expect(hex(parseRecoveryKey('ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ'))).toBe('ff'.repeat(20));
  });

  it('parse accepts lowercase/no dashes/I→1 O→0', () => {
    const variants = [
      '0123-4567-89ab-cdef-ghjk-mnpq-rstv-wxyz',
      '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
      '0123 4567 89AB CDEF GHJK MNPQ RSTV WXYZ',
      'OI23-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
      'ol23-4567-89ab-cdef-ghjk-mnpq-rstv-wxyz',
      'OL23456789abcdefGHJKmnpqRSTVwxyz',
    ];
    for (const s of variants) expect(hex(parseRecoveryKey(s)), s).toBe(ALPHABET_KEY_HEX);
  });

  it('parse ignores copy-paste noise: newlines, NBSP, zero-width spaces and en dashes', () => {
    const NBSP = chars(0xa0);
    const ZWSP = chars(0x200b);
    const EN_DASH = chars(0x2013);
    const pasted = ` 0123${EN_DASH}4567${NBSP}89AB-CDEF\nGHJK-${ZWSP}MNPQ-RSTV-WXYZ\r\n`;
    expect(hex(parseRecoveryKey(pasted))).toBe(ALPHABET_KEY_HEX);
  });

  it('parse rejects wrong lengths and characters outside Crockford base32', () => {
    const bad = [
      '',
      '0123-4567',
      '0123456789ABCDEFGHJKMNPQRSTVWXY',
      '0123456789ABCDEFGHJKMNPQRSTVWXYZ0',
      '0123456789ABCDEFGHJKMNPQRSTVWXYU',
      '0123456789ABCDEFGHJKMNPQRSTVWXY*',
      '0123456789ABCDEFGHJKMNPQRSTVWXYÜ',
    ];
    for (const s of bad) expect(() => parseRecoveryKey(s), s).toThrow(TypeError);
  });

  it('parse errors never echo the key', () => {
    const secretish = 'SECRETKEYSECRETKEYSECRETKEYSECR*';
    expect(() => parseRecoveryKey(secretish)).toThrow(TypeError);
    try {
      parseRecoveryKey(secretish);
    } catch (e) {
      expect(String((e as Error).message)).not.toContain('SECRET');
    }
  });

  it('deriveRecoveryKeys accepts only the 20-byte raw key', async () => {
    await expect(deriveRecoveryKeys(random(16))).rejects.toThrow(TypeError);
    await expect(deriveRecoveryKeys(random(32))).rejects.toThrow(TypeError);
  });

  it('createRecoveryBundle wraps the same AK under a fresh recovery key', async () => {
    const ak = random(32);
    const bundle = await createRecoveryBundle(ak);
    expect(bundle.recoveryKey).toMatch(FORMAT);
    expect(bundle.wrappedAccountKeyRecovery).toMatch(/^[A-Za-z0-9_-]{80}$/);
    const keys = await deriveRecoveryKeys(parseRecoveryKey(bundle.recoveryKey));
    expect(createHash('sha256').update(keys.authKey).digest('base64url')).toBe(
      bundle.recoveryAuthHash,
    );
    const unwrapped = await unwrapKey(
      keys.encKey,
      bundle.wrappedAccountKeyRecovery,
      AAD.WRAP_RECOVERY,
    );
    expect(hex(unwrapped)).toBe(hex(ak));
    // Rotation (R9) issues a different key every time.
    expect((await createRecoveryBundle(ak)).recoveryKey).not.toBe(bundle.recoveryKey);
  });

  it('another recovery key cannot unwrap AK', async () => {
    const bundle = await createRecoveryBundle(random(32));
    const other = await deriveRecoveryKeys(generateRecoveryKey().raw);
    await expect(
      unwrapKey(other.encKey, bundle.wrappedAccountKeyRecovery, AAD.WRAP_RECOVERY),
    ).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('createRecoveryBundle accepts only a 32-byte AK', async () => {
    await expect(createRecoveryBundle(random(31))).rejects.toThrow(TypeError);
  });
});
