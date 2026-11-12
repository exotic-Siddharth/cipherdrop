import { defineConfig, devices } from '@playwright/test';

/**
 * Smoke test of a RUNNING production stack (docker-compose.prod.yml, docs/DEPLOYMENT.md), through nginx.
 * Not part of `npm run e2e` or CI: it needs a stack to point at.
 *   SMOKE_BASE_URL=http://127.0.0.1:8080 npm run smoke:prod -w @cipherdrop/web
 * Use 127.0.0.1 or localhost over plain HTTP (WebCrypto needs a secure context and the refresh cookie is Secure),
 * and set WEB_ORIGIN of the stack to the same origin. The account it registers stays in the stack's database.
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
