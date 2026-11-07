import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  b64urlDecode,
  b64urlEncode,
  bs,
  randomBytes,
  toHex,
  utf8Decode,
  utf8Encode,
} from './encoding';

const bytes = (...xs: number[]) => new Uint8Array(xs);
const ascii = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('b64urlEncode / b64urlDecode', () => {
  it('matches the RFC 4648 test vectors, without padding', () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'Zg'],
      ['fo', 'Zm8'],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg'],
      ['fooba', 'Zm9vYmE'],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [plain, encoded] of vectors) {
      expect(b64urlEncode(ascii(plain))).toBe(encoded);
      expect(new TextDecoder().decode(b64urlDecode(encoded))).toBe(plain);
    }
  });

  it('uses the URL-safe alphabet: - and _ instead of + and /', () => {
    expect(b64urlEncode(bytes(0xfb, 0xff, 0xbf))).toBe('-_-_');
    expect(b64urlDecode('-_-_')).toEqual(bytes(0xfb, 0xff, 0xbf));
  });

  it('round-trips random data of every length from 0 to 100 bytes, as Node encodes it', () => {
    for (let n = 0; n <= 100; n++) {
      const data = new Uint8Array(nodeRandomBytes(n));
      const encoded = b64urlEncode(data);
      expect(encoded).toBe(Buffer.from(data).toString('base64url'));
      expect(hex(b64urlDecode(encoded))).toBe(hex(data));
    }
  });

  it('encodes only the bytes a subarray view covers', () => {
    expect(b64urlEncode(bytes(1, 2, 3, 4, 5).subarray(1, 4))).toBe('AgME');
  });

  it('rejects padding, the standard alphabet, whitespace and other characters', () => {
    for (const s of ['Zg==', 'Zm9v+A', 'Zm9v/A', 'Zm 9v', 'Zm9v\n', 'Zm9v.', 'Zm9vé']) {
      expect(() => b64urlDecode(s), JSON.stringify(s)).toThrow(TypeError);
    }
  });

  it('rejects impossible lengths (4n + 1 characters)', () => {
    for (const s of ['A', 'AAAAA']) expect(() => b64urlDecode(s)).toThrow(TypeError);
  });

  it('rejects non-canonical encodings whose unused trailing bits are set', () => {
    expect(b64urlDecode('Zg')).toEqual(bytes(0x66));
    expect(() => b64urlDecode('Zh')).toThrow(TypeError);
    expect(b64urlDecode('Zm8')).toEqual(bytes(0x66, 0x6f));
    expect(() => b64urlDecode('Zm9')).toThrow(TypeError);
  });

  it('rejects non-string and non-byte inputs instead of producing garbage', () => {
    expect(() => b64urlEncode('abc' as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => b64urlDecode(undefined as unknown as string)).toThrow(TypeError);
  });
});

describe('utf8Encode / utf8Decode', () => {
  it('encodes UTF-8 exactly', () => {
    expect(hex(utf8Encode('é€😀'))).toBe('c3a9e282acf09f9880');
  });

  it('round-trips text, including a leading byte-order mark and NUL', () => {
    const BOM = String.fromCharCode(0xfeff);
    const NUL = String.fromCharCode(0);
    for (const s of ['', 'ascii', 'emoji 😀 RTL עברית', `${BOM}bom first`, `nul${NUL}inside`]) {
      expect(utf8Decode(utf8Encode(s))).toBe(s);
    }
  });

  it('rejects malformed UTF-8 instead of substituting U+FFFD', () => {
    const malformed = [bytes(0xff), bytes(0xc3), bytes(0xed, 0xa0, 0x80), bytes(0xc0, 0x80)];
    for (const b of malformed) expect(() => utf8Decode(b), hex(b)).toThrow(TypeError);
  });

  it('rejects a non-string instead of encoding "undefined"', () => {
    expect(() => utf8Encode(undefined as unknown as string)).toThrow(TypeError);
  });
});

describe('randomBytes', () => {
  it('returns n bytes, beyond the 65 536-byte getRandomValues quota too', () => {
    expect(randomBytes(0)).toHaveLength(0);
    expect(randomBytes(32)).toHaveLength(32);
    const big = randomBytes(200_000);
    expect(big).toHaveLength(200_000);
    for (const start of [0, 65_536, 131_072, 196_608]) {
      expect(big.subarray(start, start + 3_000).some((x) => x !== 0)).toBe(true);
    }
  });

  it('returns fresh randomness on every call', () => {
    expect(hex(randomBytes(32))).not.toBe(hex(randomBytes(32)));
  });

  it('rejects negative, fractional and non-finite lengths', () => {
    for (const n of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => randomBytes(n), String(n)).toThrow(RangeError);
    }
  });
});

describe('toHex', () => {
  it('is lowercase with two digits per byte', () => {
    expect(toHex(bytes(0x00, 0x0f, 0xa0, 0xff))).toBe('000fa0ff');
    expect(toHex(new Uint8Array(0))).toBe('');
  });

  it('agrees with Node for random data', () => {
    const data = new Uint8Array(nodeRandomBytes(64));
    expect(toHex(data)).toBe(Buffer.from(data).toString('hex'));
  });
});

describe('bs (internal, R19)', () => {
  it('copies exactly the viewed bytes into a fresh, unshared ArrayBuffer', () => {
    const backing = bytes(9, 1, 2, 3, 9);
    const copy = bs(backing.subarray(1, 4));
    expect(copy).toEqual(bytes(1, 2, 3));
    expect(copy.byteOffset).toBe(0);
    expect(copy.buffer.byteLength).toBe(3);
    expect(copy.buffer).toBeInstanceOf(ArrayBuffer);
    backing[1] = 42;
    expect(copy[0]).toBe(1);
  });

  it('accepts a Node Buffer and a SharedArrayBuffer-backed view', () => {
    expect(bs(Buffer.from([1, 2]))).toEqual(bytes(1, 2));
    const shared = new Uint8Array(new SharedArrayBuffer(2));
    shared.set([3, 4]);
    const copy = bs(shared);
    expect(copy.buffer).toBeInstanceOf(ArrayBuffer);
    expect(copy).toEqual(bytes(3, 4));
  });
});
