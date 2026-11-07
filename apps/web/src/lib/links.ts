/**
 * Share links (spec 7.6). Link encoding and fragment parsing are cryptographic decisions and live in
 * @cipherdrop/crypto (buildShareLink / parseShareFragment); this module adds the app origin around them and
 * re-exports the pure route helpers from ./paths.
 */
import { buildShareLink, parseShareFragment } from '@cipherdrop/crypto';

export { dropPath, loginPath, reviewPath, safeNextPath, unlockPath } from './paths';

/** The SPA origin (the API is same-origin behind /api). */
export function appOrigin(): string {
  return window.location.origin;
}

/** Full share link: with a drop key `origin/d/id#<43-char key>`; password drops (dk = null) have no fragment. */
export function shareLinkFor(dropId: string, dropKey: Uint8Array | null): string {
  return buildShareLink(appOrigin(), dropId, dropKey);
}

/** The drop key from a location hash, or null when missing/incomplete ("this link is incomplete"). */
export function readShareKey(hash: string = window.location.hash): Uint8Array<ArrayBuffer> | null {
  return parseShareFragment(hash);
}
