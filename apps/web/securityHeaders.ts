/**
 * Production security headers for the SPA (spec section 12). `vite preview` serves them (vite.config.ts), so
 * e2e runs against the real CSP; nginx (deploy/, Phase P) must mirror this list with `always` (R25).
 *
 * Why each CSP source is needed:
 * - script-src 'wasm-unsafe-eval': hash-wasm compiles its Argon2id WebAssembly module at runtime.
 * - style-src 'unsafe-inline': React style props and the toast library's injected stylesheet.
 * - img-src blob: data:: decrypted image previews (blob:) and small inline SVG/data URIs.
 * - worker-src blob:: module workers are same-origin files; blob: keeps bundler-inlined workers working.
 * No inline <script> exists anywhere: the theme is applied by the external /theme-init.js (R22).
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' blob: data:",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

/** Every section 12 header that applies over plain HTTP (vite preview, e2e). */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

/**
 * HSTS is production-only (spec section 12: "HSTS (prod)"): browsers ignore it over plain HTTP, and a
 * preview served over HTTPS on localhost must not pin HSTS for every other local dev server.
 */
export const PRODUCTION_ONLY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
});

/**
 * The dev server cannot send the CSP (Vite injects an inline React Refresh preamble), but it sends every
 * other header so dev behaves like production (no-referrer, nosniff, COOP/CORP).
 */
export const DEV_SERVER_HEADERS: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(
    Object.entries(SECURITY_HEADERS).filter(([name]) => name !== 'Content-Security-Policy'),
  ),
);
