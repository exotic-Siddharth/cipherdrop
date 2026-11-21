import crypto from 'node:crypto';
import { defineConfig, devices } from '@playwright/test';
import base from './playwright.config';

/**
 * Media run: `npm run media -w @cipherdrop/web` regenerates docs/screenshots (every PNG, at deviceScaleFactor 2) and
 * records the docs/DEMO.md flow on video, which e2e/demo.media.ts turns into docs/screenshots/demo.gif with ffmpeg.
 * It is NOT part of `npm run e2e` or CI: its files end in .media.ts, which the e2e configs' default testMatch
 * (*.spec.ts) never picks up, and they write into the repository.
 *
 * Same servers as `npm run e2e` (playwright.config.ts): `vite build` + `vite preview` under the production CSP and a
 * real API on the wiped cipherdrop_e2e database, so it shares the e2e ports and cannot run next to an e2e run. The
 * specs seed that database with apps/api/prisma/seed.ts (the demo and admin accounts and their drops), create the
 * rest through the UI, freeze each browser's clock (page.clock) and keep the e2e leak guard on.
 *
 * The seeded accounts get a random password per run, never a fixed one: MEDIA_DEMO_PASSWORD and MEDIA_ADMIN_PASSWORD
 * are set here, in the runner, before the workers and the web server start (both inherit the environment), and the
 * build bakes the demo one into "Use demo account" (VITE_DEMO_CREDENTIALS) for the recorded login.
 */
process.env.MEDIA_DEMO_PASSWORD ??= `demo ${crypto.randomBytes(8).toString('hex')}`;
process.env.MEDIA_ADMIN_PASSWORD ??= `admin ${crypto.randomBytes(8).toString('hex')}`;

const servers = Array.isArray(base.webServer) ? base.webServer : [];

export default defineConfig({
  ...base,
  testMatch: '*.media.ts',
  outputDir: './test-results/media',
  timeout: 10 * 60_000,
  expect: { timeout: 30_000 },
  reporter: [['list']],
  use: { ...base.use, trace: 'off' },
  projects: [{ name: 'media', use: { ...devices['Desktop Chrome'] } }],
  webServer: servers.map((server) =>
    server.name === 'web'
      ? {
          ...server,
          env: {
            ...server.env,
            VITE_DEMO_CREDENTIALS: `demo@cipherdrop.local:${process.env.MEDIA_DEMO_PASSWORD}`,
          },
        }
      : server,
  ),
});
