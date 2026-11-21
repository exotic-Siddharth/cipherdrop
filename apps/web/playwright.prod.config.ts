import { defineConfig, devices } from '@playwright/test';

/**
 * Smoke test of a RUNNING production stack (docker-compose.prod.yml, docs/DEPLOYMENT.md), through nginx.
 * Not part of `npm run e2e`: it needs a stack to point at. CI runs it in the prod-stack job (.github/workflows/ci.yml)
 * against docker-compose.prod.yml built from the Dockerfiles and booted with generated secrets.
 *   SMOKE_BASE_URL=http://127.0.0.1:8080 npm run smoke:prod -w @cipherdrop/web
 * Use 127.0.0.1 or localhost over plain HTTP (WebCrypto needs a secure context and the refresh cookie is Secure),
 * and set WEB_ORIGIN of the stack to the same origin. Point it at nginx's own port (WEB_BIND:WEB_PORT): the
 * slow-client checks open raw sockets to it. The account and the anonymous drop it creates stay in the stack's
 * database (the drop is deleted again), and the slow-client checks take about 50 s.
 * With SMOKE_WEB_CONTAINER=<name of the web container> (and the docker CLI) it also reads nginx's access log.
 */
const baseURL = process.env.SMOKE_BASE_URL;
if (!baseURL) throw new Error('SMOKE_BASE_URL is required, e.g. http://127.0.0.1:8080');

export default defineConfig({
  testDir: './deploy-checks',
  testMatch: '*.spec.ts',
  outputDir: './test-results/prod-smoke',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  use: { baseURL, acceptDownloads: true, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
