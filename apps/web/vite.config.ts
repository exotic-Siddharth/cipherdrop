import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, type Connect, type Plugin } from 'vite';
import { DEV_SERVER_HEADERS, SECURITY_HEADERS } from './securityHeaders';

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
 * The SPA is always same-origin with the API: dev and preview proxy /api to the API (spec section 6).
 * - API_PROXY_TARGET (process env or apps/web/.env) points the proxy elsewhere, e.g. the e2e API on 4101 (R2).
 * - `vite preview` serves the production security headers, CSP included (spec section 12), so e2e proves
 *   the CSP does not break the app. HSTS is production-only (see securityHeaders.ts).
 */
export default defineConfig(({ mode }) => {
  // Prefix '' also reads non-VITE_ keys (config only: the client bundle still sees VITE_* keys only).
  const env = loadEnv(mode, webDir, '');
  const apiTarget = env.API_PROXY_TARGET || 'http://localhost:4100';
  const proxy = { '/api': { target: apiTarget } };

  return {
    plugins: [react(), tailwindcss(), securityDoc()],
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
