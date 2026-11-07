/**
 * Byte/string encodings (spec section 7: b64url = base64url WITHOUT padding; text is UTF-8).
 *
 * R19 typing: functions accept any `Uint8Array` and return `Uint8Array<ArrayBuffer>`, which is
 * assignable to `BufferSource` under TS 5.9.
 *
 * Decoding is strict, so every byte string has exactly one accepted encoding: no padding, no `+` or
 * `/`, no whitespace, and the unused low bits of the last character must be zero (RFC 4648 section
 * 3.5, canonical encoding). The server's blob schemas apply the same rule.
 */

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** ASCII code -> 6-bit value, or -1 outside the base64url alphabet. */
const B64URL_VALUES = new Int8Array(128).fill(-1);
for (let i = 0; i < B64URL_ALPHABET.length; i++) B64URL_VALUES[B64URL_ALPHABET.charCodeAt(i)] = i;

const HEX_BYTES = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/** crypto.getRandomValues refuses requests above 65 536 bytes (QuotaExceededError). */
const RANDOM_QUOTA = 65_536;

const textEncoder = new TextEncoder();
/** fatal: malformed UTF-8 throws instead of becoming U+FFFD; ignoreBOM: a leading BOM is kept. */
const textDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Encode bytes as base64url without padding. */
export function b64urlEncode(b: Uint8Array): string {
  assertBytes(b, 'b64urlEncode input');
  const a = B64URL_ALPHABET;
  const n = b.length;
  let out = '';
  let i = 0;
  for (; i + 2 < n; i += 3) {
    const v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += a[v >>> 18] + a[(v >>> 12) & 63] + a[(v >>> 6) & 63] + a[v & 63];
  }
  if (n - i === 1) {
    const v = b[i] << 16;
    out += a[v >>> 18] + a[(v >>> 12) & 63];
  } else if (n - i === 2) {
    const v = (b[i] << 16) | (b[i + 1] << 8);
    out += a[v >>> 18] + a[(v >>> 12) & 63] + a[(v >>> 6) & 63];
  }
  return out;
}

/**
 * Decode unpadded, canonical base64url. Throws TypeError on characters outside the base64url alphabet,
 * on an impossible length (4n + 1 characters) and on non-zero unused trailing bits.
 */
export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  if (typeof s !== 'string') throw new TypeError('b64urlDecode expects a string');
  const n = s.length;
  const tail = n % 4;
  if (tail === 1) throw new TypeError('Invalid base64url: impossible length');
  const out = new Uint8Array(((n - tail) / 4) * 3 + (tail === 0 ? 0 : tail - 1));
  let o = 0;
  let i = 0;
  for (; i + 4 <= n; i += 4) {
    const v =
      (sextet(s, i) << 18) | (sextet(s, i + 1) << 12) | (sextet(s, i + 2) << 6) | sextet(s, i + 3);
    out[o++] = v >>> 16;
    out[o++] = (v >>> 8) & 0xff;
    out[o++] = v & 0xff;
  }
  if (tail === 2) {
    const c0 = sextet(s, i);
    const c1 = sextet(s, i + 1);
    if (c1 & 0x0f) throw new TypeError('Invalid base64url: non-canonical final character');
    out[o] = (c0 << 2) | (c1 >>> 4);
  } else if (tail === 3) {
    const c0 = sextet(s, i);
    const c1 = sextet(s, i + 1);
    const c2 = sextet(s, i + 2);
    if (c2 & 0x03) throw new TypeError('Invalid base64url: non-canonical final character');
    out[o] = (c0 << 2) | (c1 >>> 4);
    out[o + 1] = ((c1 & 0x0f) << 4) | (c2 >>> 2);
  }
  return out;
}

/** UTF-8 encode a string. */
export function utf8Encode(s: string): Uint8Array<ArrayBuffer> {
  if (typeof s !== 'string') throw new TypeError('utf8Encode expects a string');
  return textEncoder.encode(s);
}

/** UTF-8 decode bytes. Throws TypeError on malformed UTF-8; a leading byte-order mark is preserved. */
export function utf8Decode(b: Uint8Array): string {
  assertBytes(b, 'utf8Decode input');
  return textDecoder.decode(b);
}

/** `n` cryptographically secure random bytes (crypto.getRandomValues). */
export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new RangeError(`randomBytes: n must be a non-negative integer (got ${n})`);
  }
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += RANDOM_QUOTA) {
    globalThis.crypto.getRandomValues(out.subarray(i, Math.min(n, i + RANDOM_QUOTA)));
  }
  return out;
}

/** Lowercase hex encoding (R5: used for X-Chunk-SHA256). */
export function toHex(b: Uint8Array): string {
  assertBytes(b, 'toHex input');
  let out = '';
  for (let i = 0; i < b.length; i++) out += HEX_BYTES[b[i]];
  return out;
}

/**
 * Internal (R19): copy any Uint8Array into a fresh ArrayBuffer-backed Uint8Array before every
 * `crypto.subtle` call. Not re-exported from index.ts.
 */
export function bs(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  assertBytes(u8, 'bytes');
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy;
}

/** Internal: true for any Uint8Array, including a Node Buffer or an array from another realm. */
export function isUint8Array(x: unknown): x is Uint8Array {
  return x instanceof Uint8Array || Object.prototype.toString.call(x) === '[object Uint8Array]';
}

/** Internal: throws TypeError unless `x` is a Uint8Array (of exactly `length` bytes, when given). */
export function assertBytes(x: unknown, what: string, length?: number): asserts x is Uint8Array {
  if (!isUint8Array(x)) throw new TypeError(`${what} must be a Uint8Array`);
  if (length !== undefined && x.length !== length) {
    throw new TypeError(`${what} must be ${length} bytes (got ${x.length})`);
  }
}

function sextet(s: string, i: number): number {
  const code = s.charCodeAt(i);
  const v = code < 128 ? B64URL_VALUES[code] : -1;
  if (v < 0) throw new TypeError(`Invalid base64url: unexpected character at position ${i}`);
  return v;
}
