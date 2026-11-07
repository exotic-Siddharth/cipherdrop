/**
 * App route paths and the `?next=` open-redirect guard. Pure (no crypto, no DOM): safe anywhere.
 * Share links with keys live in ./links.ts.
 */

/** `/d/<dropId>` (the receive route). */
export function dropPath(dropId: string): string {
  return `/d/${encodeURIComponent(dropId)}`;
}

/** R13: admin review of a reported drop with the reporter-supplied key: `/d/<id>?review=1#<key>`. */
export function reviewPath(dropId: string, keyB64url: string): string {
  return `${dropPath(dropId)}?review=1#${keyB64url}`;
}

/** Routes that must never be a post-login/unlock destination (they would loop). */
const NON_DESTINATIONS = ['/login', '/unlock'];

/**
 * Validate a `?next=` value: only same-origin app paths ("/..."), never "//host", "/\\host", schemes, control
 * characters or the auth pages themselves. Anything else returns `fallback`.
 */
export function safeNextPath(next: string | null | undefined, fallback = '/dashboard'): string {
  if (!next || !next.startsWith('/')) return fallback;
  // eslint-disable-next-line no-control-regex -- rejecting control characters is the point
  if (/[\u0000-\u001f\u007f]/.test(next)) return fallback;
  let decoded: string;
  try {
    decoded = decodeURIComponent(next);
  } catch {
    return fallback;
  }
  for (const candidate of [next, decoded]) {
    if (candidate.startsWith('//') || candidate.startsWith('/\\')) return fallback;
  }
  const pathname = next.split(/[?#]/, 1)[0] ?? '';
  if (NON_DESTINATIONS.some((p) => pathname === p || pathname.startsWith(`${p}/`))) return fallback;
  return next;
}

function withNext(path: string, next?: string): string {
  return next ? `${path}?next=${encodeURIComponent(next)}` : path;
}

/** `/login?next=<path>` */
export function loginPath(next?: string): string {
  return withNext('/login', next);
}

/** `/unlock?next=<path>` */
export function unlockPath(next?: string): string {
  return withNext('/unlock', next);
}
