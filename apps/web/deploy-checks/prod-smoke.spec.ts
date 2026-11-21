/**
 * Production-stack smoke test (playwright.prod.config.ts): the built SPA behind nginx, the real API, Postgres, Redis
 * and storage. It checks what the other suites cannot see: the headers nginx really sends, the SPA fallback, the
 * /api proxy limits, how nginx treats slow clients, and one end-to-end encrypted flow with the CSP enforced by a
 * real browser.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import net from 'node:net';
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

/**
 * Console messages a browser prints when the CSP blocks something or the report-only Trusted Types policy
 * reports a violation (Chromium's message for that names no policy), and uncaught page errors.
 */
function watchCsp(page: Page, sink: string[]): void {
  page.on('console', (msg) => {
    const text = msg.text();
    if (/content security policy|requires 'Trusted\w+' assignment/i.test(text)) sink.push(text);
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

/* ---- Slow clients (ops-1). Raw sockets, because a browser or APIRequestContext cannot send half a request.
   They talk to nginx's own port: a Go proxy in front (Caddy) relays an early answer to a stalled body only once
   more of the body arrives, so through it the first check sees no 429 even though nginx sent one. ---- */

const BASE = new URL(process.env.SMOKE_BASE_URL ?? 'http://127.0.0.1:8080');
/** The per-client cap of deploy/nginx.conf (`limit_conn api_ip`), read so the two cannot drift. */
const PER_CLIENT_CAP = Number(
  /limit_conn api_ip (\d+);/.exec(
    readFileSync(path.join(import.meta.dirname, '..', '..', '..', 'deploy', 'nginx.conf'), 'utf8'),
  )?.[1],
);
/** CHUNK_SIZE + 16: a full ciphertext chunk. */
const CHUNK_BYTES = 4 * 1024 * 1024 + 16;
const NO_ID = 'A'.repeat(22);

interface RawRequest {
  socket: net.Socket;
  /** Everything received so far (latin1). */
  received: () => string;
  /** The status of the first response, or null when the connection closed (or was reset) without one. */
  outcome: Promise<number | null>;
  /** The outcome so far: undefined while the request is still waiting. */
  settled: () => number | null | undefined;
  /** The connection is closed (by either side, or reset). */
  closed: Promise<void>;
}

/** Opens a connection to the stack and sends a request header (and optionally the start of a body). */
function rawRequest(
  method: string,
  target: string,
  headers: Record<string, string>,
  body = '',
): RawRequest {
  const socket = net.connect(Number(BASE.port || 80), BASE.hostname);
  socket.setNoDelay(true);
  socket.on('error', () => {}); // a reset is one of the outcomes under test
  let data = '';
  let settled: number | null | undefined;
  const closed = new Promise<void>((resolve) => socket.once('close', () => resolve()));
  const outcome = new Promise<number | null>((resolve) => {
    socket.on('data', (chunk: Buffer) => {
      data += chunk.toString('latin1');
      const status = /^HTTP\/1\.1 (\d{3}) /.exec(data)?.[1];
      if (status) resolve((settled ??= Number(status)));
    });
    socket.once('close', () => resolve((settled ??= null)));
  });
  const lines = Object.entries({ Host: BASE.host, ...headers }).map(([k, v]) => `${k}: ${v}\r\n`);
  socket.write(`${method} ${target} HTTP/1.1\r\n${lines.join('')}\r\n${body}`);
  return { socket, received: () => data, outcome, settled: () => settled, closed };
}

/** `promise`, or a failure naming `what` after `ms`. */
async function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what}: nothing after ${ms} ms`)), ms);
  });
  try {
    return await Promise.race([promise, late]);
  } finally {
    clearTimeout(timer);
  }
}

const sleep = (ms: number) =>
  new Promise<'still open'>((r) => setTimeout(() => r('still open'), ms));

test.describe('nginx and slow clients (raw sockets)', () => {
  test.skip(BASE.protocol !== 'http:', 'the raw-socket checks speak plain HTTP to SMOKE_BASE_URL');

  test('one client holds at most the per-client cap of /api slots; nginx drops a stalled JSON body in about 15 s', async ({
    request,
  }) => {
    expect(PER_CLIENT_CAP).toBeGreaterThan(0);
    // JSON requests whose body never comes: nginx counts each one once its header is in and waits for the body,
    // so they hold their slots without ever reaching the API. Two more than the cap, which nginx must refuse.
    const opened = Date.now();
    const stalled = Array.from({ length: PER_CLIENT_CAP + 2 }, () =>
      rawRequest(
        'POST',
        '/api/does-not-exist',
        {
          'Content-Type': 'application/json',
          'Content-Length': '64',
        },
        '{',
      ),
    );
    try {
      await expect
        .poll(() => stalled.filter((s) => s.settled() === 429).length, { timeout: 5_000 })
        .toBeGreaterThanOrEqual(2);
      await sleep(500);
      const held = stalled.filter((s) => s.settled() === undefined);
      // At most the cap is held: fewer only while another request of this client still holds a slot (the 413 of
      // the previous test lingers for a few seconds). Nothing but nginx's 429 was answered.
      expect(held.length).toBeLessThanOrEqual(PER_CLIENT_CAP);
      expect(held.length).toBeGreaterThanOrEqual(PER_CLIENT_CAP - 2);
      expect(stalled.every((s) => s.settled() === undefined || s.settled() === 429)).toBe(true);
      // Meanwhile every further /api request of this client is refused by nginx itself, chunk routes included.
      const refused = await request.get(`/api/drops/${NO_ID}/files/${NO_ID}/chunks/0`);
      expect(refused.status()).toBe(429);
      expect(refused.headers()['server']).toBe('nginx');
      expect(refused.headers()['x-request-id'], 'answered by nginx, not the API').toBeUndefined();

      // client_body_timeout 15s: nginx gives up on every stalled body and resets the connection, freeing the slots.
      const outcomes = await within(
        Promise.all(held.map((s) => s.outcome)),
        30_000,
        'stalled bodies',
      );
      const heldFor = Date.now() - opened;
      expect(
        outcomes.every((o) => o === null || o === 408),
        String(outcomes),
      ).toBe(true);
      expect(heldFor).toBeGreaterThan(10_000);
      expect(heldFor).toBeLessThan(25_000);
      const after = await request.get('/api/does-not-exist');
      expect(after.status()).toBe(404);
      expect(after.headers()['content-type']).toContain('application/json');
    } finally {
      for (const s of stalled) s.socket.destroy();
    }
  });

  test('a dripped chunk PUT without a valid upload token is answered by the API at once, not buffered by nginx', async () => {
    const put = rawRequest('PUT', `/api/drops/${NO_ID}/files/${NO_ID}/chunks/0`, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(CHUNK_BYTES),
      Authorization: `Bearer ${'A'.repeat(43)}`,
      'X-Chunk-SHA256': '0'.repeat(64),
    });
    // One byte every 500 ms: buffered, nginx would wait for all 4 MiB before the API saw anything.
    const drip = setInterval(() => put.socket.write('x'), 500);
    try {
      expect(await within(put.outcome, 5_000, 'response to the token-less PUT')).toBe(401);
      expect(put.received()).toMatch(/\r\nx-request-id: /i); // the API's answer
      expect(put.received()).toMatch(/\r\ncontent-type: application\/json/i);
      // ...and nginx ends its side at once, so an ordinary client closes too (this socket does on nginx's FIN). A
      // client that keeps sending anyway is read and discarded for up to lingering_time, 30 s (SECURITY.md section 7).
      await within(put.closed, 5_000, 'close after the 401');
    } finally {
      clearInterval(drip);
      put.socket.destroy();
    }
  });

  test('a verified uploader that drips its chunk body is hung up by the API minimum body rate', async ({
    request,
  }) => {
    test.setTimeout(90_000);
    // An anonymous drop with one full chunk (counts against the 10 per hour anonymous creations of this address).
    const fileId = randomBytes(16).toString('base64url');
    const created = await request.post('/api/drops', {
      data: {
        encryptedManifest: randomBytes(120).toString('base64url'),
        files: [{ id: fileId, ciphertextBytes: CHUNK_BYTES, chunkCount: 1 }],
        expiresInHours: 1,
        maxDownloads: 1,
      },
    });
    expect(created.status()).toBe(201);
    const { dropId, ownerToken, uploadToken } = (await created.json()) as Record<string, string>;
    const put = rawRequest('PUT', `/api/drops/${dropId}/files/${fileId}/chunks/0`, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(CHUNK_BYTES),
      Authorization: `Bearer ${uploadToken}`,
      'X-Chunk-SHA256': '0'.repeat(64),
    });
    const drip = setInterval(() => put.socket.write('x'), 1_000);
    const started = Date.now();
    try {
      // Accepted: the API holds an upload slot and reads the body as it comes...
      expect(await Promise.race([put.outcome, sleep(20_000)])).toBe('still open');
      // ...until a CHUNK_UPLOAD_IDLE_TIMEOUT_SEC window (30 s) brings less than 4,096 B/s and it hangs up; nginx
      // reports the upstream close as 502 or drops the connection. Buffered, the drip would go on for ever.
      const outcome = await within(put.outcome, 30_000, 'hang-up of the dripped PUT');
      expect([502, null], String(outcome)).toContain(outcome);
      expect(Date.now() - started).toBeLessThan(45_000);
    } finally {
      clearInterval(drip);
      put.socket.destroy();
      await request.delete(`/api/drops/${dropId}`, { headers: { 'X-Owner-Token': ownerToken } });
    }
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

test('Swagger UI is not served on the SPA origin; the OpenAPI JSON is', async ({ request }) => {
  for (const url of ['/api/docs', '/api/docs/', '/api/docs/swagger-ui-bundle.js']) {
    const res = await request.get(url);
    expect(res.status(), url).toBe(404);
    // nginx's own 404 (not the API's JSON one), with the SPA's section 12 headers.
    expect(res.headers()['content-type'], url).toContain('text/html');
    expect(res.headers()['content-security-policy'], url).toBe(
      SECURITY_HEADERS['Content-Security-Policy'],
    );
  }
  const spec = await request.get('/api/openapi.json');
  expect(spec.status()).toBe(200);
  expect((await spec.json()).openapi).toMatch(/^3\./);
});

test('the SPA bundle carries no demo credentials', async ({ request }) => {
  const html = await (await request.get('/')).text();
  const asset = /src="(\/assets\/[^"]+\.js)"/.exec(html)?.[1] as string;
  const js = await (await request.get(asset)).text();
  expect(js).not.toMatch(/demo@cipherdrop\.local|demo-cipherdrop/);
});
