/**
 * Production-stack smoke test (playwright.prod.config.ts): the built SPA behind nginx, the real API, Postgres, Redis
 * and storage. It checks what the other suites cannot see: the headers nginx really sends, the SPA fallback, the
 * /api proxy limits and one end-to-end encrypted flow with the CSP enforced by a real browser.
 */
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { PRODUCTION_ONLY_HEADERS, SECURITY_HEADERS } from '../securityHeaders';
import {
  downloadFromReady,
  openLink,
  randomFile,
  randomPassword,
  registerAccount,
  sendDrop,
  sha256,
  uniqueEmail,
} from '../e2e/support/flows';

const DOWNLOAD_DIR = path.join(
  import.meta.dirname,
  '..',
  'test-results',
  'prod-smoke',
  'downloads',
);

/** Console messages a browser prints when the CSP blocks something, and uncaught page errors. */
function watchCsp(page: Page, sink: string[]): void {
  page.on('console', (msg) => {
    if (/content security policy/i.test(msg.text())) sink.push(msg.text());
  });
  page.on('pageerror', (err) => sink.push(`pageerror: ${err.message}`));
}

test.describe('nginx', () => {
  test('serves the SPA with every section 12 header, and the fallback for deep links', async ({
    request,
  }) => {
    const expected = { ...SECURITY_HEADERS, ...PRODUCTION_ONLY_HEADERS };
    for (const url of ['/', '/d/AAAAAAAAAAAAAAAAAAAAAA', '/login']) {
      const res = await request.get(url);
      expect(res.status(), url).toBe(200);
      expect(res.headers()['content-type'], url).toContain('text/html');
      expect(res.headers()['cache-control'], url).toBe('no-cache');
      for (const [name, value] of Object.entries(expected)) {
        expect(res.headers()[name.toLowerCase()], `${url} ${name}`).toBe(value);
      }
      expect(res.headers()['server'], 'nginx version hidden').toBe('nginx');
    }
    const health = await request.get('/healthz');
    expect(health.status()).toBe(200);
    expect(await health.text()).toBe('ok\n');
  });

  test('hashed assets are cached for a year and a missing asset is a 404, not index.html', async ({
    request,
  }) => {
    const html = await (await request.get('/')).text();
    const asset = /src="(\/assets\/[^"]+\.js)"/.exec(html)?.[1];
    expect(asset, 'index.html references a hashed script').toBeTruthy();
    const res = await request.get(asset as string);
    expect(res.status()).toBe(200);
    expect(res.headers()['cache-control']).toBe('max-age=31536000');
    expect(res.headers()['content-type']).toMatch(/javascript/);
    expect((await request.get('/assets/does-not-exist.js')).status()).toBe(404);
  });

  test('proxies /api: JSON 404 from the API for unknown routes, headers from both layers', async ({
    request,
  }) => {
    const res = await request.get('/api/does-not-exist');
    expect(res.status()).toBe(404);
    expect(res.headers()['content-type']).toContain('application/json');
    expect(res.headers()['cache-control']).toContain('no-store');
    expect(res.headers()['strict-transport-security']).toBe(
      PRODUCTION_ONLY_HEADERS['Strict-Transport-Security'],
    );
    expect(res.headers()['permissions-policy']).toBe(SECURITY_HEADERS['Permissions-Policy']);
    expect(res.headers()['x-content-type-options']).toBe('nosniff');
  });

  test('client_max_body_size 5m: a 6 MiB body is refused by nginx, before the API', async ({
    request,
  }) => {
    const res = await request.put('/api/drops/x/files/y/chunks/0', {
      data: Buffer.alloc(6 * 1024 * 1024),
      headers: { 'content-type': 'application/octet-stream' },
    });
    expect(res.status()).toBe(413);
    expect(res.headers()['server']).toBe('nginx');
  });
});

test('account: register, send 5 MiB, reload + unlock, recipient decrypts identical bytes (CSP enforced)', async ({
  page,
  browser,
}) => {
  const cspProblems: string[] = [];
  watchCsp(page, cspProblems);
  const email = uniqueEmail('prod-smoke');
  const password = randomPassword();
  const file = randomFile('smoke-test-file.bin', 5 * 1024 * 1024);

  await registerAccount(page, email, password);
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  const link = await sendDrop(page, [file], { maxDownloads: 5 });
  expect(link).toMatch(/\/d\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/);

  await page.getByRole('link', { name: 'Dashboard', exact: true }).first().click();
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });

  // Reload: the session is refreshed from the Secure httpOnly cookie through nginx; the vault key is gone.
  await page.reload();
  await expect(page).toHaveURL(/\/unlock\?next=%2Fdashboard$/, { timeout: 30_000 });
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: /Unlock/ }).click();
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 30_000 });

  const recipientContext = await browser.newContext();
  const recipient = await recipientContext.newPage();
  watchCsp(recipient, cspProblems);
  await openLink(recipient, link);
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(sha256(saved.buffer)).toBe(sha256(file.buffer));
  expect(saved.filename).toBe(file.name);
  await expect(recipient.getByText('Integrity verified').first()).toBeVisible();
  await recipientContext.close();

  expect(cspProblems, 'no CSP violation or page error').toEqual([]);
});

test('operational endpoints are not exposed through nginx', async ({ request }) => {
  for (const url of ['/readyz', '/metrics']) {
    expect((await request.get(url)).status(), url).toBe(404);
  }
});

test('the SPA bundle carries no demo credentials', async ({ request }) => {
  const html = await (await request.get('/')).text();
  const asset = /src="(\/assets\/[^"]+\.js)"/.exec(html)?.[1] as string;
  const js = await (await request.get(asset)).text();
  expect(js).not.toMatch(/demo@cipherdrop\.local|demo-cipherdrop/);
});
