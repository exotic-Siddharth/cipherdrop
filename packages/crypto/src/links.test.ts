import { describe, expect, it } from 'vitest';
import { buildShareLink, parseShareFragment } from './links';

/** DK = bytes 0x00..0x1f; KEY = its b64url (43 chars), computed independently with Node's Buffer. */
const DK = Uint8Array.from({ length: 32 }, (_, i) => i);
const KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const DROP_ID = 'AAECAwQFBgcICQoLDA0ODw';
const ORIGIN = 'https://cipherdrop.example';
const chars = (...codes: number[]) => String.fromCharCode(...codes);
const percentEncodeAll = (s: string) =>
  [...s].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');

describe('buildShareLink', () => {
  it('puts b64url(DK) in the #fragment', () => {
    expect(buildShareLink(ORIGIN, DROP_ID, DK)).toBe(`${ORIGIN}/d/${DROP_ID}#${KEY}`);
  });

  it('has no fragment for password drops', () => {
    expect(buildShareLink(ORIGIN, DROP_ID, null)).toBe(`${ORIGIN}/d/${DROP_ID}`);
  });

  it('does not double the slash after an origin that ends with one', () => {
    expect(buildShareLink(`${ORIGIN}/`, DROP_ID, null)).toBe(`${ORIGIN}/d/${DROP_ID}`);
  });

  it('rejects a drop id outside base64url, a key that is not 32 bytes, and a missing key', () => {
    expect(() => buildShareLink(ORIGIN, '../admin', DK)).toThrow(TypeError);
    expect(() => buildShareLink(ORIGIN, `${DROP_ID}#x`, DK)).toThrow(TypeError);
    expect(() => buildShareLink(ORIGIN, '', DK)).toThrow(TypeError);
    expect(() => buildShareLink(ORIGIN, DROP_ID, DK.subarray(0, 16))).toThrow(TypeError);
    expect(() => buildShareLink(ORIGIN, DROP_ID, undefined as unknown as null)).toThrow(TypeError);
  });
});

describe('parseShareFragment', () => {
  it('recovers DK from the hash of a built link', () => {
    const { hash } = new URL(buildShareLink(ORIGIN, DROP_ID, DK));
    expect(parseShareFragment(hash)).toEqual(DK);
  });

  it('accepts the fragment with or without its leading #', () => {
    expect(parseShareFragment(`#${KEY}`)).toEqual(DK);
    expect(parseShareFragment(KEY)).toEqual(DK);
  });

  it('tolerates trailing punctuation, rejects truncated', () => {
    const tails = ['.', ')', ',', ').', '),', '!', '?', '"', "'", ']', '>', ' ', '\n', '\t', '...'];
    const encodedTails = ['%20', '%29', '%2E%29', '%0A', chars(0x2026)];
    for (const tail of [...tails, ...encodedTails]) {
      expect(parseShareFragment(`#${KEY}${tail}`), JSON.stringify(tail)).toEqual(DK);
    }
    const truncated = [KEY.slice(0, 42), KEY.slice(0, 42) + '.', KEY.slice(0, 20), '', '#'];
    for (const t of truncated) expect(parseShareFragment(`#${t}`), t).toBeNull();
  });

  it('URL-decodes the fragment', () => {
    expect(parseShareFragment(`#${percentEncodeAll(KEY)}`)).toEqual(DK);
    expect(parseShareFragment(`#${KEY.slice(0, 40)}${percentEncodeAll(KEY.slice(40))}%29`)).toEqual(
      DK,
    );
  });

  it('returns null for every other shape and never throws', () => {
    const others: unknown[] = [
      `#${KEY}A`,
      `#A${KEY}`,
      `#${KEY.slice(0, 21)}.${KEY.slice(22)}`,
      `#${KEY.slice(0, 42)}9`,
      `#${KEY.replace('A', '+')}`,
      '#%E0%A4%A',
      '#%',
      '##',
      undefined,
      null,
      42,
    ];
    for (const input of others) {
      expect(() => parseShareFragment(input as string)).not.toThrow();
      expect(parseShareFragment(input as string), String(input)).toBeNull();
    }
  });

  it('stays linear on hostile input (no regex backtracking)', () => {
    const started = performance.now();
    expect(parseShareFragment(`#${'.'.repeat(200_000)}a`)).toBeNull();
    expect(parseShareFragment(`#${KEY}${')'.repeat(200_000)}`)).toEqual(DK);
    expect(performance.now() - started).toBeLessThan(2_000);
  });
});
