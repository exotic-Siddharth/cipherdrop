import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

/**
 * E2E (spec section 14, R2): Playwright drives `vite build && vite preview` (production headers, CSP on)
 * against an isolated API: port 4101, database cipherdrop_e2e, Redis DB 9, rate limits off.
 * Both servers start fresh (reuseExistingServer: false) on fixed strict ports, so a stray dev server can never
 * be tested by mistake. The specs live in ./e2e (I2). The cipherdrop_e2e database must exist and be migrated
 * before the specs touch it (e2e global setup, I2).
 */
export const E2E_API_PORT = 4101;
export const E2E_WEB_PORT = 5184;

const API_URL = `http://localhost:${E2E_API_PORT}`;
const WEB_URL = `http://localhost:${E2E_WEB_PORT}`;

const require = createRequire(import.meta.url);
const webDir = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = path.resolve(webDir, '..', '..');
// Quoted absolute paths: both contain spaces on this machine ("Program Files", "Web Projects"). No npx.
const node = JSON.stringify(process.execPath);
const vite = JSON.stringify(
  path.join(path.dirname(require.resolve('vite/package.json')), 'bin', 'vite.js'),
);

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI
    ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]]
    : [['list']],
  use: {
    baseURL: WEB_URL,
    acceptDownloads: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      name: 'api',
      command: `${node} --import tsx apps/api/src/index.ts`,
      cwd: repoRoot,
      url: `${API_URL}/healthz`,
      reuseExistingServer: false,
      timeout: 120_000,
      stdout: 'ignore',
      stderr: 'pipe',
      env: {
        NODE_ENV: 'development',
        API_PORT: String(E2E_API_PORT),
        WEB_ORIGIN: WEB_URL,
        DATABASE_URL:
          'postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_e2e?schema=public',
        REDIS_URL: 'redis://localhost:56380/9',
        KEY_PREFIX: 'cd-e2e',
        RATE_LIMITS_ENABLED: 'false',
        // Relative STORAGE_DIR resolves against apps/api (gitignored apps/api/data/).
        STORAGE_DIR: './data/e2e-blobs',
        STORAGE_DRIVER: 'local',
        LOG_LEVEL: 'warn',
      },
    },
    {
      name: 'web',
      command: `${node} ${vite} build && ${node} ${vite} preview --port ${E2E_WEB_PORT} --strictPort`,
      cwd: webDir,
      url: WEB_URL,
      reuseExistingServer: false,
      timeout: 180_000,
      stdout: 'ignore',
      stderr: 'pipe',
      env: { API_PROXY_TARGET: API_URL },
    },
  ],
});
