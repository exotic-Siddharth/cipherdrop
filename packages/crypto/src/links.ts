/**
 * Share links (spec section 7.6). The key travels in the #fragment, which browsers never send to servers.
 *
 * With a key: `${origin}/d/${dropId}#${b64url(DK)}` (43-char fragment). Password drops: `${origin}/d/${dropId}`.
 */
import { KEY_BYTES, SHARE_KEY_CHARS } from './constants';
import { assertBytes, b64urlDecode, b64urlEncode } from './encoding';

/** A drop id is a base64url path segment (the server issues b64url(16 bytes)). */
const DROP_ID_RE = /^[A-Za-z0-9_-]+$/;

/** Build a share link; pass `null` for password-protected drops (no fragment). */
export function buildShareLink(origin: string, dropId: string, dk: Uint8Array | null): string {
  if (typeof origin !== 'string' || origin.length === 0) {
    throw new TypeError('origin must be a non-empty string');
  }
  if (typeof dropId !== 'string' || !DROP_ID_RE.test(dropId)) {
    throw new TypeError('dropId must be base64url');
  }
  let end = origin.length;
  while (end > 0 && origin.charCodeAt(end - 1) === 0x2f) end--;
  const link = `${origin.slice(0, end)}/d/${dropId}`;
  if (dk === null) return link;
  assertBytes(dk, 'dk', KEY_BYTES);
  return `${link}#${b64urlEncode(dk)}`;
}

/**
 * Parse `location.hash`: strip a leading '#', URL-decode, strip trailing characters outside the base64url
 * alphabet (chat apps append '.', ')' or ','), then require exactly 43 chars decoding to 32 bytes.
 * Anything else returns null (the UI shows "this link is incomplete"). Never throws.
 */
export function parseShareFragment(hash: string): Uint8Array<ArrayBuffer> | null {
  if (typeof hash !== 'string') return null;
  let s = hash.startsWith('#') ? hash.slice(1) : hash;
  try {
    s = decodeURIComponent(s);
  } catch {
    // Not valid percent-encoding: keep the text as it is (trailing junk is stripped below).
  }
  // A linear scan, not /[^A-Za-z0-9_-]+$/: that regex backtracks quadratically on a hostile fragment.
  let end = s.length;
  while (end > 0 && !isB64urlCode(s.charCodeAt(end - 1))) end--;
  if (end !== SHARE_KEY_CHARS) return null;
  try {
    const dk = b64urlDecode(s.slice(0, end));
    return dk.length === KEY_BYTES ? dk : null;
  } catch {
    return null;
  }
}

function isB64urlCode(c: number): boolean {
  return (
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) || // a-z
    (c >= 0x30 && c <= 0x39) || // 0-9
    c === 0x2d || // -
    c === 0x5f // _
  );
}
