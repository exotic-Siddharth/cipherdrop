/** The leak guard is only worth something if it can fail: prove it catches each kind of leak. */
import { randomBytes } from 'node:crypto';
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { LeakGuard, test as guarded, textVariants } from './support/fixtures';

function guardWith(body: string | Buffer, url = 'http://localhost:5184/api/drops'): LeakGuard {
  const guard = new LeakGuard();
  guard.requests.push({
    method: 'POST',
    url,
    headers: 'content-type: application/json',
    body: Buffer.from(body),
  });
  return guard;
}

/**
 * A 32-byte key whose standard base64 has '+' and '/' (and, like every 32-byte value, '=' padding), so it
 * differs from the base64url text in the link: the case a text-only check misses.
 */
function awkwardKey(): Buffer {
  return Buffer.concat([Buffer.from([0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff]), randomBytes(26)]);
}

/** A same-origin API call the page makes itself, so the browser adds the cookies (the API answers 404). */
const UNKNOWN_DROP = '/api/drops/AAAAAAAAAAAAAAAAAAAAAA';
const apiCall = (): Promise<number> =>
  fetch('/api/drops/AAAAAAAAAAAAAAAAAAAAAA').then((r) => r.status);

/**
 * Runs `steps` in a fresh context of the real browser, watched by a new guard that only allows the web
 * origin, then waits for the full headers of every request.
 */
async function browse(
  browser: Browser,
  baseURL: string | undefined,
  steps: (page: Page, context: BrowserContext) => Promise<void>,
): Promise<LeakGuard> {
  if (!baseURL) throw new Error('baseURL is not configured');
  const guard = new LeakGuard({ origins: [baseURL] });
  const context = await browser.newContext({ baseURL });
  guard.watch(context);
  try {
    await steps(await context.newPage(), context);
    await guard.settle();
  } finally {
    await context.close();
  }
  return guard;
}

test.describe('leak guard', () => {
  test('finds a plaintext name in a JSON body', () => {
    const guard = guardWith(JSON.stringify({ name: 'tax-return-2025.pdf' }));
    guard.forbidText('file name', 'tax-return-2025.pdf');
    expect(guard.findLeaks()).toHaveLength(1);
  });

  test('finds a URL-encoded name in a query string and a base64 name in a body', () => {
    const name = 'héllo wörld.txt';
    const inUrl = guardWith('{}', `http://localhost:5184/api/x?q=${encodeURIComponent(name)}`);
    inUrl.forbidText('file name', name);
    expect(inUrl.findLeaks()).toHaveLength(1);
    const inBody = guardWith(Buffer.from(name, 'utf8').toString('base64'));
    inBody.forbidText('file name', name);
    expect(inBody.findLeaks()).toHaveLength(1);
  });

  test('finds plaintext bytes inside a binary body and the key in a header', () => {
    const plain = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef', 'utf8');
    const guard = guardWith(Buffer.concat([Buffer.from([1, 2, 3]), plain, Buffer.from([4])]));
    guard.forbidBytes('plaintext bytes', plain);
    expect(guard.findLeaks()).toHaveLength(1);
    const keyGuard = new LeakGuard();
    keyGuard.requests.push({
      method: 'GET',
      url: 'http://x/api/y',
      headers: 'x-k: KEY123',
      body: null,
    });
    keyGuard.forbidText('key', 'KEY123');
    expect(keyGuard.findLeaks()).toHaveLength(1);
  });

  test('finds plaintext bytes re-encoded as base64url or hex', () => {
    // Starts with bytes whose base64url ('-', '_') differs from standard base64 ('+', '/').
    const plain = Buffer.concat([
      Buffer.from([0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff]),
      randomBytes(60),
    ]);
    const hex = plain.toString('hex');
    for (const leak of [plain.toString('base64url'), hex, hex.toUpperCase()]) {
      const guard = guardWith(JSON.stringify({ blob: `prefix${leak}suffix` }));
      guard.forbidBytes('plaintext bytes', plain);
      expect(guard.findLeaks(), leak.slice(0, 12)).toEqual([
        'plaintext bytes found in POST /api/drops',
      ]);
    }
  });

  test('finds a key re-encoded as hex or as standard base64 with +, / and =', () => {
    const bytes = awkwardKey();
    const linkKey = bytes.toString('base64url');
    const b64 = bytes.toString('base64');
    expect(b64).toMatch(/\+/);
    expect(b64).toMatch(/\//);
    expect(b64).toMatch(/=$/);
    const leaks = {
      'lower-case hex body': guardWith(JSON.stringify({ k: bytes.toString('hex') })),
      'upper-case hex body': guardWith(bytes.toString('hex').toUpperCase()),
      'standard base64 body': guardWith(JSON.stringify({ k: b64 })),
      'unpadded base64 body': guardWith(`k=${b64.replace(/=+$/, '')}&x=1`),
      "JSON '\\/' escape": guardWith(`{"k":"${b64.replaceAll('/', '\\/')}"}`),
      'URL-encoded base64 query': guardWith(
        '{}',
        `http://localhost:5184/api/x?k=${encodeURIComponent(b64)}`,
      ),
      'raw key bytes': guardWith(Buffer.concat([Buffer.from([0, 1]), bytes, Buffer.from([2])])),
    };
    for (const [how, guard] of Object.entries(leaks)) {
      guard.forbidKey('link key', linkKey);
      expect(guard.findLeaks(), how).toHaveLength(1);
    }
    // forbidText sees only encodings of the TEXT: this is why the specs use forbidKey for keys.
    const textOnly = guardWith(JSON.stringify({ k: b64, h: bytes.toString('hex') }));
    textOnly.forbidText('link key', linkKey);
    expect(textOnly.findLeaks()).toEqual([]);
  });

  test('stays quiet for unrelated bodies', () => {
    const guard = guardWith('{"encryptedManifest":"AAAA"}');
    guard.forbidText('file name', 'tax-return-2025.pdf');
    guard.forbidKey('link key', awkwardKey());
    guard.forbidBytes('plaintext bytes', randomBytes(64));
    expect(guard.findLeaks()).toEqual([]);
    expect(textVariants('a b').length).toBeGreaterThan(1);
  });

  test('keeps and notes a request whose full headers cannot be read', async () => {
    const guard = new LeakGuard();
    const request = (allHeaders: () => Promise<Record<string, string>>) => ({
      url: () => 'http://localhost:5184/api/x#fragment-is-not-sent',
      method: () => 'GET',
      headers: () => ({ 'x-k': 'KEY123' }),
      allHeaders,
      postDataBuffer: () => null,
    });
    guard.record(
      request(() => Promise.reject(new Error('Target page, context or browser closed'))),
    );
    guard.record(request(() => new Promise(() => {})));
    await guard.settle(50);
    guard.forbidText('key', 'KEY123');
    guard.forbidText('fragment', 'fragment-is-not-sent');
    // Both requests are scanned with their provisional headers; the URLs lost their fragment.
    expect(guard.findLeaks()).toEqual(['key found in GET /api/x', 'key found in GET /api/x']);
    expect(guard.notes).toHaveLength(2);
    expect(guard.notes[0]).toContain('allHeaders() failed');
    expect(guard.notes[1]).toContain('no full headers after 50 ms');
  });
});

test.describe('leak guard in the browser', () => {
  test('finds the key in a Cookie header (request.headers() leaves cookies out)', async ({
    browser,
    baseURL,
  }) => {
    const key = randomBytes(32).toString('base64url');
    const guard = await browse(browser, baseURL, async (page, context) => {
      await context.addCookies([{ name: 'k', value: key, url: baseURL as string }]);
      await page.goto('/SECURITY.md');
      await page.evaluate(apiCall);
    });
    guard.forbidKey('link key', key);
    expect(guard.findLeaks()).toEqual([
      'link key found in GET /SECURITY.md',
      `link key found in GET ${UNKNOWN_DROP}`,
    ]);
  });

  test('finds a file name or a key in a navigation or asset URL outside /api', async ({
    browser,
    baseURL,
  }) => {
    const name = 'board minutes, final.pdf';
    const key = awkwardKey();
    const guard = await browse(browser, baseURL, async (page) => {
      await page.goto(`/SECURITY.md?name=${name}`);
      const src = `/favicon.svg?k=${encodeURIComponent(key.toString('base64'))}`;
      await Promise.all([
        page.waitForRequest((r) => r.url().includes('/favicon.svg')),
        page.evaluate((s) => {
          const img = new Image();
          img.src = s;
          document.body.append(img);
        }, src),
      ]);
    });
    guard.forbidText('file name', name);
    guard.forbidKey('link key', key);
    expect(guard.findLeaks()).toEqual([
      'file name found in GET /SECURITY.md?name=board%20minutes,%20final.pdf',
      expect.stringMatching(/^link key found in GET \/favicon\.svg\?k=/),
    ]);
    expect(guard.findForeign()).toEqual([]);
  });

  test('reports a request to another origin', async ({ browser, baseURL }) => {
    const guard = await browse(browser, baseURL, async (page, context) => {
      // Answered by the route: nothing leaves this machine.
      await context.route('http://cdn.example.test/**', (route) =>
        route.fulfill({ contentType: 'text/plain', body: 'ok' }),
      );
      await page.goto('http://cdn.example.test/lib.js?v=1');
    });
    expect(guard.findForeign()).toEqual(['GET http://cdn.example.test/lib.js?v=1']);
  });

  test('stays quiet for data: and blob: URLs, which never reach a server', async ({
    browser,
    baseURL,
  }) => {
    const name = 'holiday-photo-2026.svg';
    const guard = await browse(browser, baseURL, async (page) => {
      await page.goto('/SECURITY.md');
      await page.evaluate(async (title) => {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><title>${title}</title></svg>`;
        const fromData = new Image();
        fromData.src = `data:image/svg+xml,${encodeURIComponent(svg)}`;
        const fromBlob = new Image();
        fromBlob.src = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
        await Promise.all([fromData.decode(), fromBlob.decode()]);
      }, name);
    });
    guard.forbidText('file name', name);
    expect(guard.requests.map((r) => r.url)).toEqual([`${new URL(baseURL!).origin}/SECURITY.md`]);
    expect(guard.findLeaks()).toEqual([]);
    expect(guard.findForeign()).toEqual([]);
  });
});

guarded(
  'the fixtures watch the default context and read every header',
  async ({ page, context, leaks, baseURL }) => {
    const key = randomBytes(32).toString('base64url');
    await context.addCookies([{ name: 'k', value: key, url: baseURL as string }]);
    await page.goto('/SECURITY.md');
    await page.evaluate(apiCall);
    await leaks.settle();
    leaks.forbidKey('link key', key);
    expect(leaks.findLeaks()).toEqual([
      'link key found in GET /SECURITY.md',
      `link key found in GET ${UNKNOWN_DROP}`,
    ]);
    // The leak was planted: take the key off the list so the guard's own verdict after the test passes.
    leaks.forbidden.splice(0);
  },
);
