import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, type Connect, type Plugin } from 'vite';
import { DEV_SERVER_HEADERS, SECURITY_HEADERS } from './securityHeaders';
import { SECURITY_TXT_PATH, securityTxt, type SecurityTxtConfig } from './securityTxt';

const webDir = fileURLToPath(new URL('.', import.meta.url));
const securityDocFile = fileURLToPath(new URL('../../docs/SECURITY.md', import.meta.url));

/**
 * /how-it-works links to the threat model. This plugin serves the repository's docs/SECURITY.md at
 * /SECURITY.md as UTF-8 plain text from the dev and preview servers (with the same headers as the rest of
 * each server) and copies it into the build output, where deploy/nginx.conf serves it as text/plain.
 */
function securityDoc(): Plugin {
  const serve =
    (headers: Readonly<Record<string, string>>): Connect.NextHandleFunction =>
    (req, res, next) => {
      const isRead = req.method === 'GET' || req.method === 'HEAD';
      if (!isRead || req.url?.split('?')[0] !== '/SECURITY.md') return next();
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      res.end(req.method === 'HEAD' ? undefined : readFileSync(securityDocFile));
    };
  return {
    name: 'cipherdrop-security-doc',
    configureServer(server) {
      server.middlewares.use(serve(DEV_SERVER_HEADERS));
    },
    configurePreviewServer(server) {
      server.middlewares.use(serve(SECURITY_HEADERS));
    },
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'SECURITY.md',
        source: readFileSync(securityDocFile, 'utf8'),
      });
    },
  };
}

/**
 * /.well-known/ (RFC 8615): security.txt (RFC 9116, securityTxt.ts) from SECURITY_TXT_CONTACT and SECURITY_TXT_POLICY,
 * generated per request by the dev server, written into the build output (deploy/nginx.conf serves it from there) and
 * served from that output by the preview server, as UTF-8 plain text with the same headers as the rest of each server.
 * Every other /.well-known/ path is a 404 on both servers, as in nginx: never the SPA's index.html.
 */
function wellKnown(config: SecurityTxtConfig): Plugin {
  // An invalid contact or policy fails `vite`, `vite build` and `vite preview` at start-up, not a request later.
  securityTxt(config);
  const serve =
    (
      headers: Readonly<Record<string, string>>,
      read: () => string | undefined,
    ): Connect.NextHandleFunction =>
    (req, res, next) => {
      const pathname = req.url?.split('?')[0] ?? '';
      if (!pathname.startsWith('/.well-known/')) return next();
      const isRead = req.method === 'GET' || req.method === 'HEAD';
      const body = isRead && pathname === SECURITY_TXT_PATH ? read() : undefined;
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      res.statusCode = body === undefined ? 404 : 200;
      res.end(req.method === 'HEAD' ? undefined : (body ?? 'Not Found\n'));
    };
  return {
    name: 'cipherdrop-well-known',
    configureServer(server) {
      server.middlewares.use(serve(DEV_SERVER_HEADERS, () => securityTxt(config)));
    },
    configurePreviewServer(server) {
      const built = path.resolve(
        server.config.root,
        server.config.build.outDir,
        SECURITY_TXT_PATH.slice(1),
      );
      const read = () => {
        try {
          return readFileSync(built, 'utf8');
        } catch {
          return undefined;
        }
      };
      server.middlewares.use(serve(SECURITY_HEADERS, read));
    },
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: SECURITY_TXT_PATH.slice(1),
        source: securityTxt(config),
      });
    },
  };
}

/**
 * The SPA is always same-origin with the API: dev and preview proxy /api to the API (spec section 6).
 * - API_PROXY_TARGET (process env or apps/web/.env) points the proxy elsewhere, e.g. the e2e API on 4101 (R2).
 * - `vite preview` serves the production security headers, CSP included (spec section 12), so e2e proves
 *   the CSP does not break the app. HSTS is production-only (see securityHeaders.ts).
 * - SECURITY_TXT_CONTACT and SECURITY_TXT_POLICY (process env or apps/web/.env) fill /.well-known/security.txt.
 */
export default defineConfig(({ mode }) => {
  // Prefix '' also reads non-VITE_ keys (config only: the client bundle still sees VITE_* keys only).
  const env = loadEnv(mode, webDir, '');
  const apiTarget = env.API_PROXY_TARGET || 'http://localhost:4100';
  const proxy = { '/api': { target: apiTarget } };

  return {
    plugins: [
      react(),
      tailwindcss(),
      securityDoc(),
      wellKnown({ contact: env.SECURITY_TXT_CONTACT, policy: env.SECURITY_TXT_POLICY }),
    ],
    server: {
      port: 5174,
      strictPort: true,
      proxy,
      headers: { ...DEV_SERVER_HEADERS },
    },
    preview: {
      port: 5174,
      strictPort: true,
      proxy,
      headers: { ...SECURITY_HEADERS },
    },
    worker: { format: 'es' },
    build: {
      target: 'es2022',
      sourcemap: false,
      // The CSP says font-src 'self': a font inlined as a data: URI would be blocked, so never inline assets.
      assetsInlineLimit: 0,
      // The lazily loaded password-strength dictionaries form one large on-demand chunk by design.
      chunkSizeWarningLimit: 1600,
    },
  };
});
