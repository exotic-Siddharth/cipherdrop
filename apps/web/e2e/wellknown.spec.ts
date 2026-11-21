/**
 * /.well-known/ on the preview server (vite.config.ts wellKnown(); deploy/nginx.conf does the same, see
 * deploy-checks): the generated security.txt (RFC 9116) as UTF-8 plain text with the production headers, and a 404
 * for every other path there, never the SPA's index.html with a 200.
 */
import { SECURITY_HEADERS } from '../securityHeaders';
import { expect, test } from './support/fixtures';

const YEAR_MS = 365 * 86_400_000;

test('serves /.well-known/security.txt as plain text, with a contact and an Expires within a year', async ({
  request,
}) => {
  const res = await request.get('/.well-known/security.txt');
  expect(res.status()).toBe(200);
  expect(res.headers()['content-type']).toBe('text/plain; charset=utf-8');
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    expect(res.headers()[name.toLowerCase()], name).toBe(value);
  }
  const text = await res.text();
  expect(text).not.toContain('<div id="root">');
  expect(text).toMatch(/^Contact: (?:mailto:|tel:|https:\/\/)\S+$/m);
  expect(text).toMatch(/^Policy: https:\/\/\S+$/m);
  const expires = Date.parse(/^Expires: (\S+)$/m.exec(text)?.[1] ?? '');
  expect(expires).toBeGreaterThan(Date.now());
  expect(expires - Date.now()).toBeLessThan(YEAR_MS);
  // HEAD as well (some scanners only send HEAD first).
  const head = await request.head('/.well-known/security.txt');
  expect(head.status()).toBe(200);
  expect(head.headers()['content-type']).toBe('text/plain; charset=utf-8');
});

test('every other /.well-known/ path is a 404, not the SPA', async ({ request }) => {
  for (const url of [
    '/.well-known/',
    '/.well-known/change-password',
    '/.well-known/security.txt/x',
    '/.well-known/SECURITY.TXT',
  ]) {
    const res = await request.get(url);
    expect(res.status(), url).toBe(404);
    expect(await res.text(), url).not.toContain('<div id="root">');
  }
  // The SPA fallback itself is unchanged.
  const spa = await request.get('/how-it-works');
  expect(spa.status()).toBe(200);
  expect(await spa.text()).toContain('<div id="root">');
});
