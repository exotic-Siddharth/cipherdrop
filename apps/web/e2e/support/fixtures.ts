/**
 * Shared Playwright fixtures (spec section 14).
 *
 * - `newContext()` creates fresh browser contexts (a recipient with no session, a second device) that are
 *   watched like the default one and closed after the test.
 * - The leak guard records EVERY request of every watched context: document navigations, scripts, styles,
 *   images, worker scripts, the requests workers make (the upload worker's chunk PUTs) and the API calls. For
 *   each it keeps the URL, every header the browser sent (request.allHeaders(), so Cookie too) and the body
 *   bytes. After the test it fails when a forbidden value appears in any of them (plaintext file names,
 *   plaintext file bytes, the key after `#`, passwords) or when a request went to another origin. This is the
 *   e2e half of "no plaintext metadata reaches the server" (the reviewers check request payloads in the
 *   traces). The server half, what the API writes to its logs, is apps/api/src/modules/{auth,drops}/
 *   logs.test.ts.
 * - Uncaught page errors and CSP violations (the preview build runs with the production CSP) fail the test.
 */
import {
  test as base,
  expect,
  type BrowserContext,
  type Page,
  type Request,
} from '@playwright/test';

export interface CapturedRequest {
  method: string;
  /** Without the #fragment: browsers never send it. */
  url: string;
  /** Every header as `name: value` lines. */
  headers: string;
  body: Buffer | null;
}

export interface Forbidden {
  label: string;
  /** Every needle is searched as UTF-8 bytes in the URL, the header values and the body. */
  values: (string | Buffer)[];
}

/** What record() reads from a Playwright request (a structural type, so the self-tests can fake one). */
export type RecordableRequest = Pick<
  Request,
  'url' | 'method' | 'headers' | 'allHeaders' | 'postDataBuffer'
>;

export interface LeakGuardOptions {
  /** The origins the app may talk to (the web origin). findForeign() reports a request anywhere else. */
  origins?: string[];
}

/**
 * The same text in the encodings a leak could take: raw, URL-encoded (as encodeURIComponent, encodeURI and an
 * HTML form encode it), JSON-escaped, base64, base64url.
 */
export function textVariants(text: string): string[] {
  const buf = Buffer.from(text, 'utf8');
  return [
    ...new Set([
      text,
      encodeURIComponent(text),
      encodeURI(text),
      new URLSearchParams({ v: text }).toString().slice(2),
      JSON.stringify(text).slice(1, -1),
      buf.toString('base64'),
      buf.toString('base64url'),
    ]),
  ].filter((v) => v.length > 0);
}

/** `name: value` lines, close to what goes on the wire (no JSON escaping in the way of a raw needle). */
const headerLines = (headers: Record<string, string>): string =>
  Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');

const pathOf = (url: string) => url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i, '');
const firstLine = (err: unknown) =>
  (err instanceof Error ? err.message : String(err)).split('\n')[0];

/** How long settle() waits for the full headers before it falls back to the provisional ones. */
const SETTLE_TIMEOUT_MS = 10_000;

export class LeakGuard {
  readonly requests: CapturedRequest[] = [];
  readonly forbidden: Forbidden[] = [];
  readonly problems: string[] = [];
  /** Requests whose full headers could not be read: their provisional headers() were scanned instead. */
  readonly notes: string[] = [];
  private readonly origins: Set<string>;
  /** Requests still waiting for request.allHeaders(). */
  private readonly pending = new Map<CapturedRequest, Promise<void>>();

  constructor(options: LeakGuardOptions = {}) {
    this.origins = new Set((options.origins ?? []).map((o) => new URL(o).origin));
  }

  forbidText(label: string, text: string): void {
    this.forbidden.push({ label, values: textVariants(text) });
  }

  /**
   * Plaintext bytes: the first `length` bytes raw, and re-encoded as standard base64, base64url and lower-
   * and upper-case hex. The base64 needles cover a multiple of 3 bytes, so they also match inside the base64
   * of a longer buffer that starts with these bytes (no padding, no partial last character).
   */
  forbidBytes(label: string, bytes: Buffer, length = 48): void {
    const head = Buffer.from(bytes.subarray(0, Math.min(length, bytes.length)));
    const aligned = head.length >= 3 ? head.subarray(0, head.length - (head.length % 3)) : head;
    const hex = head.toString('hex');
    this.forbidden.push({
      label,
      values: [
        head,
        ...new Set([
          aligned.toString('base64'),
          aligned.toString('base64url'),
          hex,
          hex.toUpperCase(),
        ]),
      ],
    });
  }

  /**
   * A key, as the share link carries it (base64url text) or as raw bytes. forbidText() alone would only catch
   * that text and encodings OF THE TEXT; a leak may just as well re-encode the key BYTES. So this forbids the
   * text variants plus the bytes raw, as standard base64 with and without '=' padding, as base64url, and as
   * lower- and upper-case hex, each also URL-encoded (standard base64 has '+', '/' and '=') and with the
   * '\/' escape some JSON encoders write for '/'.
   */
  forbidKey(label: string, key: string | Uint8Array): void {
    const bytes = typeof key === 'string' ? Buffer.from(key, 'base64url') : Buffer.from(key);
    if (bytes.length === 0 || (typeof key === 'string' && bytes.toString('base64url') !== key)) {
      throw new Error(`forbidKey(${label}): expected base64url text or bytes`);
    }
    const b64 = bytes.toString('base64');
    const hex = bytes.toString('hex');
    const encodings = [
      b64,
      b64.replace(/=+$/, ''),
      bytes.toString('base64url'),
      hex,
      hex.toUpperCase(),
    ];
    const values = new Set<string>(typeof key === 'string' ? textVariants(key) : []);
    for (const s of encodings) {
      values.add(s);
      values.add(encodeURIComponent(s));
      values.add(s.replaceAll('/', '\\/'));
    }
    this.forbidden.push({ label, values: [bytes, ...values] });
  }

  watch(context: BrowserContext): void {
    // Requests of dedicated workers (the upload and KDF workers) are reported on their page's context too.
    context.on('request', (request) => this.record(request));
    const watchPage = (page: Page) => {
      page.on('pageerror', (err) => this.problems.push(`pageerror: ${err.message}`));
      page.on('console', (msg) => {
        const text = msg.text();
        if (/Content Security Policy|Refused to (load|execute|connect|apply|create)/i.test(text)) {
          this.problems.push(`CSP: ${text.slice(0, 240)}`);
        }
      });
    };
    context.on('page', watchPage);
    for (const page of context.pages()) watchPage(page);
  }

  /** Captures one request (watch() calls this for every request; public for the self-tests). */
  record(request: RecordableRequest): void {
    const url = request.url();
    // data: and blob: URLs are resolved inside the browser: they are not network requests, nothing reaches a
    // server, and a data: URL legitimately holds decrypted content (an image preview).
    if (/^(data|blob):/i.test(url)) return;
    const captured: CapturedRequest = {
      method: request.method(),
      // Chromium already reports the URL without the fragment; strip it anyway, it is never sent.
      url: url.replace(/#.*$/s, ''),
      // headers() leaves out Cookie and the other headers the browser adds; record() starts with them and
      // allHeaders() below replaces them with every header that went out.
      headers: headerLines(request.headers()),
      body: request.postDataBuffer(),
    };
    this.requests.push(captured);
    const done = request.allHeaders().then(
      (all) => {
        captured.headers = headerLines(all);
      },
      (err: unknown) => {
        this.notes.push(
          `${captured.method} ${pathOf(captured.url)}: allHeaders() failed (${firstLine(err)}), ` +
            'only the provisional headers() were scanned',
        );
      },
    );
    this.pending.set(
      captured,
      done.finally(() => this.pending.delete(captured)),
    );
  }

  /**
   * Waits until every captured request has its full headers. allHeaders() answers once the browser has sent
   * the request; when its page or context closed first, or nothing comes within the timeout, the request
   * keeps its provisional headers (those the page set itself) and gets a note: it is never dropped.
   */
  async settle(timeoutMs = SETTLE_TIMEOUT_MS): Promise<void> {
    if (this.pending.size === 0) return;
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, timeoutMs);
    });
    await Promise.race([Promise.all(this.pending.values()), deadline]);
    clearTimeout(timer);
    for (const captured of this.pending.keys()) {
      this.notes.push(
        `${captured.method} ${pathOf(captured.url)}: no full headers after ${timeoutMs} ms, ` +
          'only the provisional headers() were scanned',
      );
    }
    this.pending.clear();
  }

  /** A description of every forbidden value found in a captured request. */
  findLeaks(): string[] {
    const hits: string[] = [];
    for (const req of this.requests) {
      const haystacks: Buffer[] = [Buffer.from(req.url), Buffer.from(req.headers)];
      if (req.body) haystacks.push(req.body);
      for (const f of this.forbidden) {
        for (const v of f.values) {
          const needle = typeof v === 'string' ? Buffer.from(v, 'utf8') : v;
          if (needle.length === 0) continue;
          if (haystacks.some((h) => h.includes(needle))) {
            hits.push(`${f.label} found in ${req.method} ${pathOf(req.url)}`);
            break;
          }
        }
      }
    }
    return hits;
  }

  /** Every request to an origin outside `options.origins` (nothing when no origin was given). */
  findForeign(): string[] {
    if (this.origins.size === 0) return [];
    return this.requests
      .filter((r) => !this.origins.has(new URL(r.url).origin))
      .map((r) => `${r.method} ${r.url}`);
  }

  count(method: string, pathPart: string): number {
    return this.requests.filter((r) => r.method === method && r.url.includes(pathPart)).length;
  }
}

interface Fixtures {
  leaks: LeakGuard;
  newContext: () => Promise<BrowserContext>;
  guard: void;
}

export const test = base.extend<Fixtures>({
  leaks: async ({ baseURL }, provide) => {
    await provide(new LeakGuard({ origins: baseURL ? [baseURL] : [] }));
  },
  // Both context fixtures depend on `guard`, so they close their contexts BEFORE the guard's verdict: every
  // request a closing page still makes is recorded, and no allHeaders() call is left waiting on a live page.
  context: async ({ context, leaks, guard: _guard }, provide) => {
    leaks.watch(context);
    await provide(context);
  },
  newContext: async ({ browser, leaks, guard: _guard }, provide) => {
    const created: BrowserContext[] = [];
    await provide(async () => {
      const ctx = await browser.newContext({ acceptDownloads: true });
      leaks.watch(ctx);
      created.push(ctx);
      return ctx;
    });
    for (const ctx of created) await ctx.close();
  },
  guard: [
    async ({ leaks }, provide, testInfo) => {
      await provide();
      await leaks.settle();
      for (const note of leaks.notes) {
        testInfo.annotations.push({ type: 'leak-guard', description: note });
        console.warn(`leak guard: ${note}`);
      }
      expect(leaks.problems, 'uncaught page errors or CSP violations').toEqual([]);
      expect(leaks.findLeaks(), 'plaintext or key material found in a request').toEqual([]);
      expect(leaks.findForeign(), 'requests to another origin').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
