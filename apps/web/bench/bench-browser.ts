/**
 * Browser throughput bench (spec section 14 `bench`, docs/BENCHMARKS.md): one headless Chromium driven by
 * Playwright against a RUNNING production build served by `vite preview` (production CSP) and the API behind
 * its /api proxy. It measures what a user's browser does, through the real UI:
 *
 *   - Argon2id derive time in the kdf worker: the gap between the prelogin response and the login request of
 *     the login form (the form derives authKey in the worker in between). The first derive of a page includes
 *     starting the worker and compiling the hash-wasm module ("cold"); later derives of the same page reuse the
 *     worker ("warm"). 64 MiB, t=3, p=1 (KDF_DEFAULT).
 *   - encrypt + upload of a BENCH_SIZE_MIB MiB random file as a signed-in user (click on "Encrypt & upload" until
 *     the success card shows), 3 chunks in flight in the upload worker.
 *   - download + decrypt of the same file in a fresh browser context without a session (click on "Decrypt &
 *     download" until the browser's download event, i.e. all chunks fetched, decrypted and handed over as a Blob).
 *     The saved file's SHA-256 is compared with the original outside the timers.
 *
 * It registers its own throw-away account through the UI and deletes it (and so its drops) at the end through
 * DELETE /me. Rates are MiB/s (1 MiB = 1,048,576 bytes) of plaintext.
 *
 * Start the stack first (from the repo root), then run:
 *   npm run build -w @cipherdrop/web && npm run preview -w @cipherdrop/web      # serves http://localhost:5174
 *   npm run bench:browser -w @cipherdrop/web
 * Env: BENCH_WEB_URL (default http://localhost:5174), BENCH_SIZE_MIB (96), BENCH_RUNS (3).
 * One untimed warm-up transfer (8 MiB) runs first; every run uses a fresh browser context.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { b64urlEncode, deriveAccountKeys, type KdfParams } from '@cipherdrop/crypto';

const MiB = 1024 * 1024;
const BASE = (process.env.BENCH_WEB_URL ?? 'http://localhost:5174').replace(/\/$/, '');
const SIZE_MIB = Number(process.env.BENCH_SIZE_MIB ?? 96);
const RUNS = Number(process.env.BENCH_RUNS ?? 3);
if (![SIZE_MIB, RUNS].every((n) => Number.isInteger(n) && n >= 1)) {
  throw new Error('BENCH_SIZE_MIB and BENCH_RUNS must be positive integers');
}

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const fmt = (xs: number[], digits: number) =>
  `${median(xs).toFixed(digits)} | ${Math.min(...xs).toFixed(digits)} | ${Math.max(...xs).toFixed(digits)}`;
const sha256 = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');

const problems: string[] = [];

async function newContext(browser: Browser): Promise<BrowserContext> {
  const ctx = await browser.newContext({
    baseURL: BASE,
    viewport: { width: 1280, height: 900 },
    acceptDownloads: true,
  });
  // Time the derive from inside the page: the prelogin response arrives, the login request leaves.
  await ctx.addInitScript(() => {
    const w = window as unknown as { __bench: { preloginEnd: number; loginStart: number } };
    w.__bench = { preloginEnd: 0, loginStart: 0 };
    const original = window.fetch.bind(window);
    window.fetch = async (...args: Parameters<typeof fetch>) => {
      const url = args[0] instanceof Request ? args[0].url : String(args[0]);
      if (/\/api\/auth\/login$/.test(url)) w.__bench.loginStart = performance.now();
      const res = await original(...args);
      if (/\/api\/auth\/prelogin$/.test(url)) w.__bench.preloginEnd = performance.now();
      return res;
    };
  });
  return ctx;
}

function watch(page: Page, tag: string): void {
  page.on('pageerror', (e) => problems.push(`${tag} pageerror: ${e.message}`));
  page.on('console', (m) => {
    // Failed HTTP loads are reported by the response listener below (with the URL).
    if (m.type() === 'error' && !m.text().startsWith('Failed to load resource')) {
      problems.push(`${tag} console.error: ${m.text()}`);
    }
  });
  page.on('response', (r) => {
    const { pathname } = new URL(r.url());
    // A visitor without a session gets 401 from the silent refresh on every page load: expected.
    if (r.status() >= 400 && !(r.status() === 401 && pathname === '/api/auth/refresh')) {
      problems.push(`${tag} ${r.status()} ${r.request().method()} ${pathname}`);
    }
  });
}

async function register(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/register');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('group', { name: 'Your recovery key' }).waitFor({ timeout: 60_000 });
  await page.getByLabel('I saved my recovery key').check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForURL(/\/dashboard$/, { timeout: 30_000 });
}

/** Log in through the form and return the derive time (ms) measured inside the page. */
async function logIn(page: Page, email: string, password: string): Promise<number> {
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Log in', exact: true }).click();
  await page.waitForURL(/\/dashboard$/, { timeout: 60_000 });
  return page.evaluate(() => {
    const b = (window as unknown as { __bench: { preloginEnd: number; loginStart: number } })
      .__bench;
    return b.loginStart - b.preloginEnd;
  });
}

async function signOutToLogin(page: Page): Promise<void> {
  await page.getByRole('button', { name: /account menu$/ }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  // Client-side navigation keeps the page (and the kdf worker) alive, so the next derive is "warm".
  await page.evaluate(() => {
    window.history.pushState({}, '', '/login');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
  await page.getByRole('button', { name: 'Log in', exact: true }).waitFor();
}

async function send(page: Page, file: string): Promise<{ link: string; ms: number }> {
  await page
    .locator('a[href="/"]:visible', { hasText: /^Send$/ })
    .first()
    .click();
  await page.getByTestId('file-input').setInputFiles(file);
  const button = page.getByRole('button', { name: 'Encrypt & upload' });
  const started = Date.now();
  await button.click();
  await page.getByText('Your encrypted link is ready').waitFor({ timeout: 600_000 });
  const ms = Date.now() - started;
  return { link: await page.getByLabel('Share link').inputValue(), ms };
}

async function receive(
  browser: Browser,
  link: string,
  outDir: string,
): Promise<{ ms: number; msWithLoad: number; saved: Buffer }> {
  const ctx = await newContext(browser);
  const page = await ctx.newPage();
  watch(page, 'receiver');
  const loadStarted = Date.now();
  await page.goto(link);
  const button = page.getByRole('button', { name: 'Decrypt & download' });
  await button.waitFor({ timeout: 60_000 });
  const downloadEvent = page.waitForEvent('download', { timeout: 600_000 });
  const started = Date.now();
  await button.click();
  const confirm = page.getByRole('button', { name: 'Download now' });
  if (await confirm.isVisible({ timeout: 1_500 }).catch(() => false)) await confirm.click();
  const download = await downloadEvent;
  const now = Date.now();
  const file = path.join(outDir, `dl-${now}`);
  await download.saveAs(file);
  const saved = fs.readFileSync(file);
  fs.rmSync(file);
  await ctx.close();
  return { ms: now - started, msWithLoad: now - loadStarted, saved };
}

async function deleteAccount(email: string, password: string): Promise<void> {
  const api = async (p: string, init: RequestInit): Promise<unknown> => {
    const res = await fetch(`${BASE}/api${p}`, {
      ...init,
      headers: { 'content-type': 'application/json', ...(init.headers as object) },
    });
    if (!res.ok) throw new Error(`${p} -> ${res.status}`);
    return res.status === 204 ? null : res.json();
  };
  const { kdf } = (await api('/auth/prelogin', {
    method: 'POST',
    body: JSON.stringify({ email }),
  })) as { kdf: KdfParams };
  const { authKey } = await deriveAccountKeys(password, kdf);
  const body = JSON.stringify({ authKey: b64urlEncode(authKey) });
  const login = (await api('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, authKey: b64urlEncode(authKey) }),
  })) as { accessToken: string };
  await api('/me', {
    method: 'DELETE',
    body,
    headers: { authorization: `Bearer ${login.accessToken}` },
  });
}

async function main(): Promise<void> {
  const email = `bench-${Date.now().toString(36)}@bench.cipherdrop.test`;
  const password = `bench ${crypto.randomBytes(6).toString('hex')} horse battery`;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherdrop-bench-'));
  const files = {
    warm: path.join(work, 'warm.bin'),
    big: path.join(work, 'big.bin'),
  };
  const warmBytes = crypto.randomBytes(8 * MiB);
  const bigBytes = crypto.randomBytes(SIZE_MIB * MiB);
  fs.writeFileSync(files.warm, warmBytes);
  fs.writeFileSync(files.big, bigBytes);
  const bigHash = sha256(bigBytes);
  const warmHash = sha256(warmBytes);

  const browser = await chromium.launch();
  const version = browser.version();
  const cold: number[] = [];
  const warm: number[] = [];
  const up: number[] = [];
  const down: number[] = [];
  const downWithLoad: number[] = [];
  try {
    // Account, and an untimed warm-up transfer (JIT, HTTP connections, disk cache).
    const setup = await newContext(browser);
    const setupPage = await setup.newPage();
    watch(setupPage, 'setup');
    await register(setupPage, email, password);
    const w = await send(setupPage, files.warm);
    const wr = await receive(browser, w.link, work);
    if (sha256(wr.saved) !== warmHash)
      throw new Error('warm-up download differs from the original');
    await setup.close();

    for (let r = 0; r < RUNS; r++) {
      const ctx = await newContext(browser);
      const page = await ctx.newPage();
      watch(page, `run${r + 1}`);
      await page.goto('/login');
      cold.push(await logIn(page, email, password));
      for (let k = 0; k < 2; k++) {
        await signOutToLogin(page);
        warm.push(await logIn(page, email, password));
      }
      const sent = await send(page, files.big);
      up.push(SIZE_MIB / (sent.ms / 1000));
      const got = await receive(browser, sent.link, work);
      if (sha256(got.saved) !== bigHash)
        throw new Error('downloaded file differs from the original');
      down.push(SIZE_MIB / (got.ms / 1000));
      downWithLoad.push(SIZE_MIB / (got.msWithLoad / 1000));
      await ctx.close();
      console.error(
        `  run ${r + 1}/${RUNS}: derive cold ${cold.at(-1)?.toFixed(0)} ms, warm ${warm
          .slice(-2)
          .map((x) => x.toFixed(0))
          .join('/')} ms, ` +
          `up ${up.at(-1)?.toFixed(1)} MiB/s, down ${down.at(-1)?.toFixed(1)} MiB/s`,
      );
    }
  } finally {
    await browser.close();
    fs.rmSync(work, { recursive: true, force: true });
    await deleteAccount(email, password).catch((e: unknown) =>
      console.error('cleanup failed:', e instanceof Error ? e.message : e),
    );
  }

  const lines = [
    `Browser bench: Chromium ${version} headless (Playwright), Node ${process.version}, ${process.platform}/${process.arch}, ${os.cpus()[0]?.model.trim()}; ${BASE}`,
    `(${SIZE_MIB} MiB random file, ${Math.ceil((SIZE_MIB * MiB) / (4 * MiB))} chunks of 4 MiB, signed-in sender, ${RUNS} runs after one 8 MiB warm-up)`,
    '',
    '| Operation | Median | Min | Max |',
    '|---|---:|---:|---:|',
    `| Argon2id derive, cold (first in the page, ms) | ${fmt(cold, 0)} |`,
    `| Argon2id derive, warm (worker reused, ms) | ${fmt(warm, 0)} |`,
    `| Encrypt + upload (MiB/s) | ${fmt(up, 1)} |`,
    `| Download + decrypt, click to download event (MiB/s) | ${fmt(down, 1)} |`,
    `| Download + decrypt, incl. page load (MiB/s) | ${fmt(downWithLoad, 1)} |`,
    '',
    `Raw: ${JSON.stringify({ cold: cold.map(Math.round), warm: warm.map(Math.round), up: up.map((x) => Number(x.toFixed(1))), down: down.map((x) => Number(x.toFixed(1))), downWithLoad: downWithLoad.map((x) => Number(x.toFixed(1))) })}`,
    `Console errors / page errors: ${problems.length}${problems.length ? `\n${problems.join('\n')}` : ''}`,
  ];
  console.log(lines.join('\n'));
}

main().catch((err: unknown) => {
  console.error('BENCH FAILED:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
