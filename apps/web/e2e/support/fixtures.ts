/**
 * Shared Playwright fixtures (spec section 14).
 *
 * - `newContext()` creates fresh browser contexts (a recipient with no session, a second device) that are
 *   watched like the default one and closed after the test.
 * - The leak guard records EVERY request of every watched context (URL, headers, body bytes; requests made by
 *   the upload worker included) and, after the test, fails when a forbidden value appears in any of them:
 *   plaintext file names, plaintext file bytes, the key after `#`, passwords. This is the e2e half of
 *   "no plaintext metadata reaches the server" (the reviewers check request payloads in the traces).
 * - Uncaught page errors and CSP violations (the preview build runs with the production CSP) fail the test.
 */
import { test as base, expect, type BrowserContext, type Request } from '@playwright/test';

export interface CapturedRequest {
  method: string;
  url: string;
  headers: string;
  body: Buffer | null;
}

export interface Forbidden {
  label: string;
  /** Every needle is searched as UTF-8 bytes in the URL, the header values and the body. */
  values: (string | Buffer)[];
}

/** The same text in the encodings a leak could take: raw, URL-encoded, JSON-escaped, base64, base64url. */
export function textVariants(text: string): string[] {
  const buf = Buffer.from(text, 'utf8');
  return [
    ...new Set([
      text,
      encodeURIComponent(text),
      JSON.stringify(text).slice(1, -1),
      buf.toString('base64'),
      buf.toString('base64url'),
    ]),
  ].filter((v) => v.length > 0);
}

export class LeakGuard {
  readonly requests: CapturedRequest[] = [];
  readonly forbidden: Forbidden[] = [];
  readonly problems: string[] = [];

  forbidText(label: string, text: string): void {
    this.forbidden.push({ label, values: textVariants(text) });
  }

  forbidBytes(label: string, bytes: Buffer, length = 48): void {
    const head = bytes.subarray(0, Math.min(length, bytes.length));
    this.forbidden.push({
      label,
      values: [Buffer.from(head), Buffer.from(head.toString('base64'), 'utf8')],
    });
  }

  watch(context: BrowserContext): void {
    const onRequest = (request: Request) => {
      // Only the API matters for "what reaches the server"; static assets carry no payload.
      if (!request.url().includes('/api/')) return;
      this.requests.push({
        method: request.method(),
        url: request.url(),
        headers: JSON.stringify(request.headers()),
        body: request.postDataBuffer(),
      });
    };
    context.on('request', onRequest);
    const watchPage = (page: import('@playwright/test').Page) => {
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

  /** Throws a description of every forbidden value found in a captured request. */
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
            hits.push(
              `${f.label} found in ${req.method} ${req.url.replace(/^https?:\/\/[^/]+/, '')}`,
            );
            break;
          }
        }
      }
    }
    return hits;
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
  leaks: async ({ browserName: _browserName }, provide) => {
    await provide(new LeakGuard());
  },
  context: async ({ context, leaks }, provide) => {
    leaks.watch(context);
    await provide(context);
  },
  newContext: async ({ browser, leaks }, provide) => {
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
    async ({ leaks }, provide) => {
      await provide();
      expect(leaks.problems, 'uncaught page errors or CSP violations').toEqual([]);
      expect(leaks.findLeaks(), 'plaintext or key material found in a request').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
