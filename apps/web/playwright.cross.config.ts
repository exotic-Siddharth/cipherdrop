import { defineConfig, devices, type Project } from '@playwright/test';
import base from './playwright.config';

/**
 * Cross-engine e2e: `npm run e2e:cross -w @cipherdrop/web` (CI job e2e-cross runs one project per runner). Same
 * servers, database and leak guard as `npm run e2e` (playwright.config.ts), which stays desktop Chromium only.
 *
 * Only the tests tagged @cross in their title run here: the receive side and what differs between engines. Module
 * workers under the production CSP, hash-wasm Argon2id under 'wasm-unsafe-eval', a non-extractable CryptoKey posted
 * from the KDF worker to the page, the STREAM integrity check, the Blob + <a download> save, the refusal of files
 * over 256 MiB without the File System Access API (C-03), the layout at phone widths, and the leak guard's own CSP
 * check (each engine words its console report differently).
 *
 * What this is not: Playwright's WebKit is the WebKit engine built for Linux, not Safari, and the two mobile projects
 * emulate a phone's viewport, user agent and touch on a desktop engine (Chromium and WebKit), not Android Chrome or
 * iOS Safari. Results are reported as Firefox, WebKit, mobile Chromium and mobile WebKit.
 *
 * Browsers: `npm run e2e:install:cross -w @cipherdrop/web` (Chromium, Firefox and WebKit; add --with-deps on a fresh
 * Linux machine). One project: `npm run e2e:cross -w @cipherdrop/web -- --project=webkit`.
 */
export const CROSS_TAG = '@cross';

const cross = (name: string, device: (typeof devices)[string]): Project => ({
  name,
  use: { ...device },
  grep: new RegExp(CROSS_TAG),
});

export default defineConfig({
  ...base,
  outputDir: './test-results/cross',
  projects: [
    cross('firefox', devices['Desktop Firefox']),
    cross('webkit', devices['Desktop Safari']),
    cross('mobile-chromium', devices['Pixel 7']),
    cross('mobile-webkit', devices['iPhone 14']),
  ],
});
