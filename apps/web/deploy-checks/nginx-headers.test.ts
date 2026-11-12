// @vitest-environment node
/**
 * deploy/nginx.conf must send exactly the section 12 headers that `vite preview` sends in e2e
 * (securityHeaders.ts, R25). Header names and values are compared literally, so a change to one side that is not
 * mirrored in the other fails here instead of shipping a CSP that e2e never exercised.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { PRODUCTION_ONLY_HEADERS, SECURITY_HEADERS } from '../securityHeaders';

const conf = readFileSync(
  path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    '..',
    'deploy',
    'nginx.conf',
  ),
  'utf8',
);

/** add_header lines of a config fragment, as [name, value, flags]. */
function addHeaders(fragment: string): [string, string, string][] {
  return [...fragment.matchAll(/^\s*add_header\s+(\S+)\s+"([^"]*)"\s*([^;]*);/gm)].map((m) => [
    m[1] as string,
    m[2] as string,
    (m[3] as string).trim(),
  ]);
}

// Server-level headers: everything before the first `location`; the /api block is sliced separately.
const at = (directive: string): number => conf.indexOf(`\n    ${directive}`);
const serverLevel = conf.slice(0, at('location'));
const apiBlock = conf.slice(at('location /api/ '), at('location /assets/ '));

describe('deploy/nginx.conf', () => {
  it('sends exactly the section 12 headers of securityHeaders.ts, with `always`', () => {
    const expected = { ...SECURITY_HEADERS, ...PRODUCTION_ONLY_HEADERS };
    const found = addHeaders(serverLevel);
    expect(Object.fromEntries(found.map(([name, value]) => [name, value]))).toEqual(expected);
    expect(found).toHaveLength(Object.keys(expected).length);
    expect(found.every(([, , flags]) => flags === 'always')).toBe(true);
  });

  it('the /api block adds only HSTS and Permissions-Policy, with the same values', () => {
    const found = Object.fromEntries(addHeaders(apiBlock).map(([name, value]) => [name, value]));
    expect(found).toEqual({
      'Strict-Transport-Security': PRODUCTION_ONLY_HEADERS['Strict-Transport-Security'],
      'Permissions-Policy': SECURITY_HEADERS['Permissions-Policy'],
    });
    expect(apiBlock).toContain('proxy_hide_header Strict-Transport-Security;');
  });

  it('only the /api block overrides the inherited headers', () => {
    const locations = conf.slice(at('location')).replace(apiBlock, '');
    expect(addHeaders(locations)).toEqual([]);
  });

  it('proxies /api with the 5 MiB body limit (4 MiB + 16 B chunk PUT, 1 MB JSON)', () => {
    expect(apiBlock).toMatch(/client_max_body_size\s+5m;/);
    expect(apiBlock).toMatch(/proxy_pass\s+\$api_upstream;/);
  });

  it('serves /SECURITY.md (linked from /how-it-works) as UTF-8 plain text, never the SPA', () => {
    const block = conf.slice(at('location = /SECURITY.md '), at('location / '));
    expect(block).toMatch(/types \{ \}/);
    expect(block).toMatch(/default_type text\/plain;/);
    expect(block).toMatch(/charset utf-8;/);
    expect(block).toMatch(/try_files \$uri =404;/);
  });

  it('does not compress JSON (BREACH) and serves the SPA fallback', () => {
    expect(conf).not.toMatch(/gzip_types[^;]*json/);
    expect(conf).toMatch(/try_files \$uri \$uri\/ \/index\.html;/);
  });
});
