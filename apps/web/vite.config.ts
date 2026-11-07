import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';
import { DEV_SERVER_HEADERS, SECURITY_HEADERS } from './securityHeaders';

const webDir = fileURLToPath(new URL('.', import.meta.url));

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
    plugins: [react(), tailwindcss()],
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
      // The lazily loaded password-strength dictionaries form one large on-demand chunk by design.
      chunkSizeWarningLimit: 1600,
    },
  };
});
