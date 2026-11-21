// @vitest-environment node
/**
 * deploy/nginx.conf must send exactly the section 12 headers that `vite preview` sends in e2e
 * (securityHeaders.ts, R25). Header names and values are compared literally, so a change to one side that is not
 * mirrored in the other fails here instead of shipping a CSP that e2e never exercised.
 *
 * It must also keep the API's slow-client defences working behind it (ops-1): a per-client connection cap, chunk
 * transfers streamed rather than buffered, and the real client address behind Caddy. Those checks read the API's
 * own sources and docker-compose.prod.yml, so a change on one side that is not mirrored on the other fails here.
 */
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LIMITS } from '@cipherdrop/shared';
import { describe, expect, it } from 'vitest';
import { ipPrefix } from '../../api/src/lib/ip';
import { PRODUCTION_ONLY_HEADERS, SECURITY_HEADERS } from '../securityHeaders';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (...parts: string[]) => readFileSync(path.join(repo, ...parts), 'utf8');
const conf = read('deploy', 'nginx.conf');

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

/* ---- Block structure: nginx inherits array directives (add_header, limit_conn, ...) only into a block that
   declares none of its own, so the checks below look at each block's own level. ---- */

/** The config without comments (`#` outside a quoted string starts one). */
function stripComments(text: string): string {
  return text.replace(/^((?:[^#"\n]|"[^"\n]*")*)#.*$/gm, '$1');
}

/** Body of the first block whose header (the text before `{`) is exactly `header`; braces in quotes do not count. */
function block(text: string, header: string): string {
  const open = text.search(
    new RegExp(`(^|[;{}])\\s*${header.replace(/[.*+?^$()|[\]\\/]/g, '\\$&')}\\s*\\{`),
  );
  if (open < 0) throw new Error(`no block "${header}"`);
  const start = text.indexOf('{', open + 1) + 1;
  let depth = 1;
  let quoted = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') quoted = !quoted;
    else if (quoted) continue;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return text.slice(start, i);
  }
  throw new Error(`unclosed block "${header}"`);
}

/** The directives of a block's own level: every nested block (header included) removed. */
function ownLevel(body: string): string {
  let out = '';
  let depth = 0;
  let quoted = false;
  for (const ch of body) {
    if (depth === 0 && !(ch === '{' && !quoted)) out += ch;
    if (ch === '"') quoted = !quoted;
    else if (quoted) continue;
    else if (ch === '{') {
      if (depth++ === 0) out = out.replace(/[^;{}]*$/, '');
    } else if (ch === '}') depth--;
  }
  return out;
}

/**
 * Arguments of every `name ...;` directive of a level, in order. The level is split into statements at each `;`, `{`
 * and `}` outside quotes, like nginx does: a directive right after another one of the same name is its own statement,
 * and a `;` inside a quoted value (HSTS's "max-age=...; includeSubDomains") is part of the value.
 */
function directive(level: string, name: string): string[] {
  const named = new RegExp(`^${name.replace(/ /g, '\\s+')}\\s+([\\s\\S]*)$`);
  return [...level.matchAll(/((?:[^;{}"]|"[^"]*")*)([;{}])/g)]
    .filter((m) => m[2] === ';')
    .map((m) => named.exec((m[1] as string).trim())?.[1])
    .filter((args): args is string => args !== undefined);
}

/** nginx size ("5m", "128k", "4096") in bytes. */
function bytes(size: string): number {
  const m = /^(\d+)([km]?)$/i.exec(size);
  if (!m) throw new Error(`not an nginx size: ${size}`);
  return Number(m[1]) * ({ '': 1, k: 1024, m: 1024 * 1024 }[(m[2] as string).toLowerCase()] ?? NaN);
}

/** nginx time ("15s", "60", "1m") in seconds. */
function seconds(time: string): number {
  const m = /^(\d+)(s|m)?$/.exec(time);
  if (!m) throw new Error(`not an nginx time: ${time}`);
  return Number(m[1]) * (m[2] === 'm' ? 60 : 1);
}

const code = stripComments(conf);
const httpLevel = ownLevel(code);
const server = block(code, 'server');
const serverOwn = ownLevel(server);
const api = block(server, 'location /api/');
const apiOwn = ownLevel(api);
// The chunk location nested in /api/ (empty when missing, so each check below fails on its own).
const chunkHeader = /location\s+~\s+(\S+)\s*\{/.exec(api);
const chunkOwn = chunkHeader ? ownLevel(block(api, `location ~ ${chunkHeader[1]}`)) : '';
const chunkRe = new RegExp(chunkHeader?.[1] ?? '$^');

/** What a block nested in /api/ effectively sends or sets: its own list if it declares one, else /api/'s. */
function effective(name: string, own: string): string[] {
  const mine = directive(own, name);
  return mine.length > 0 ? mine : directive(apiOwn, name);
}

/** The default of one of the API's integer settings (apps/api/src/config/env.ts). */
function apiDefault(name: string): number {
  const m = new RegExp(`${name}: int\\((\\d+)`).exec(
    read('apps', 'api', 'src', 'config', 'env.ts'),
  );
  if (!m) throw new Error(`no default for ${name} in env.ts`);
  return Number(m[1]);
}

/** A top-level service's block of docker-compose.prod.yml (its lines up to the next service). */
const compose = read('docker-compose.prod.yml');
function service(name: string): string {
  const m = new RegExp(`^  ${name}:\\n((?:(?:    .*)?\\n)*)`, 'm').exec(compose);
  if (!m) throw new Error(`no service ${name}`);
  return m[1] as string;
}

const ipv4 = (s: string) => s.split('.').reduce((n, part) => n * 256 + Number(part), 0);
function inCidr(ip: string, cidr: string): boolean {
  const [net, len] = cidr.split('/') as [string, string];
  const size = 2 ** (32 - Number(len));
  return Math.floor(ipv4(ip) / size) === Math.floor(ipv4(net) / size);
}

describe('deploy/nginx.conf slow-client defences (ops-1)', () => {
  it('reads every directive of a level: one right after another of the same name, `;` in quotes', () => {
    const level = ownLevel('a 1;a 2;\n  a "x; y" z; b { a 3; }a 4; ab 5; limit_conn  api_ip 6;');
    expect(directive(level, 'a')).toEqual(['1', '2', '"x; y" z', '4']);
    expect(directive(level, 'limit_conn api_ip')).toEqual(['6']);
  });

  it('caps in-flight /api requests per client: the API per-IP chunk shares plus 16 ordinary requests', () => {
    expect(httpLevel).toMatch(/limit_conn_zone \$api_client zone=api_ip:\d+[km];/);
    const [cap] = directive(apiOwn, 'limit_conn api_ip').map(Number);
    const [total] = directive(apiOwn, 'limit_conn api_total').map(Number);
    const shares =
      apiDefault('MAX_CHUNK_UPLOADS_PER_IP') + apiDefault('MAX_CHUNK_DOWNLOADS_PER_IP');
    expect(shares).toBe(48);
    expect(cap).toBe(shares + 16);
    expect(cap as number).toBeLessThan(total as number);
    expect(directive(apiOwn, 'limit_conn_status')).toEqual(['429']);
    // Nothing nested in /api/ declares its own limit_conn, which would drop both inherited caps.
    expect(directive(chunkOwn, 'limit_conn')).toEqual([]);
  });

  it('keys the per-client cap like the API ipShareKey: an IPv4 address, or the IPv6 /48', () => {
    const map = block(code, 'map $binary_remote_addr $api_client');
    const entries = [...map.matchAll(/"~([^"]+)"\s+\$(\w+);/g)].map(
      ([, re, value]) => [new RegExp(re as string), value as string] as const,
    );
    expect(map).toMatch(/default\s+\$binary_remote_addr;/);
    // The same regex semantics as nginx's PCRE on the raw bytes of $binary_remote_addr (latin1: one char per byte).
    const key = (addr: number[]): string => {
      const raw = Buffer.from(addr).toString('latin1');
      for (const [re, value] of entries) {
        const m = re.exec(raw);
        if (m) return m.groups?.[value] ?? '';
      }
      return raw;
    };
    const v6 = (...groups: number[]) => groups.flatMap((g) => [g >> 8, g & 0xff]);
    const v4 = [198, 51, 100, 7];
    expect(key(v4)).toBe(Buffer.from(v4).toString('latin1'));
    expect(key(v6(0, 0, 0, 0, 0, 0xffff, 0xc633, 0x6407))).toBe(key(v4));
    // One /48 is one client, however many addresses it rotates through; the next /48 is another one.
    const a = key(v6(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 1));
    expect(a).toHaveLength(6);
    expect(key(v6(0x2001, 0xdb8, 0x1234, 0xffff, 1, 2, 3, 4))).toBe(a);
    expect(key(v6(0x2001, 0xdb8, 0x1235, 0x5678, 0, 0, 0, 1))).not.toBe(a);
    // Bytes PCRE's `.` would skip (a newline) are still part of the key.
    expect(key(v6(0x2001, 0x0a0a, 0x0a0a, 0, 0, 0, 0, 1))).toHaveLength(6);
  });

  it('streams chunk PUTs and GETs in a location nested in /api/ that matches exactly the API chunk routes', () => {
    const routes = read('apps', 'api', 'src', 'modules', 'drops', 'routes.ts');
    for (const method of ['put', 'get']) {
      expect(routes).toMatch(
        new RegExp(`method: '${method}',\\s*path: '/:id/files/:fileId/chunks/:index'`),
      );
    }
    const source = /const CHUNK_PATH_RE = \/(.+)\/;/.exec(
      read('apps', 'api', 'src', 'app.ts'),
    )?.[1];
    const apiChunkPath = new RegExp(source ?? '$^');
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const samples = [
      `/api/drops/${id}/files/${id}/chunks/0`,
      `/api/drops/${id}/files/${id}/chunks/123456/`,
      `/api/drops/${id}/files/${id}/chunks/`,
      `/api/drops/${id}/files/${id}/chunks`,
      `/api/drops/${id}/files/${id}/chunks/0/x`,
      `/api/drops/${id}/upload-status`,
      `/api/drops/${id}/complete`,
      `/api/drops/${id}`,
      `/api/drops`,
      `/api/auth/login`,
    ];
    for (const p of samples) {
      expect(chunkRe.test(p), p).toBe(apiChunkPath.test(p.slice('/api'.length)));
    }
    expect(chunkRe.test(samples[0] as string)).toBe(true);

    expect(directive(chunkOwn, 'proxy_request_buffering')).toEqual(['off']);
    expect(directive(chunkOwn, 'proxy_buffering')).toEqual(['off']);
    expect(directive(chunkOwn, 'proxy_pass')).toEqual(['$api_upstream']);
    // `set` is not inherited by nested locations, so the upstream is set once at server level.
    expect(directive(serverOwn, 'set')).toEqual(['$api_upstream http://api:4100']);
    expect(directive(apiOwn, 'set')).toEqual([]);
  });

  it('allows a 4 MiB + 16 B chunk body but only 1 MiB of JSON, and gives JSON bodies the shorter timeout', () => {
    const [chunkMax] = directive(chunkOwn, 'client_max_body_size').map(bytes);
    const [jsonMax] = directive(apiOwn, 'client_max_body_size').map(bytes);
    expect(chunkMax as number).toBeGreaterThanOrEqual(LIMITS.MAX_CHUNK_BYTES);
    expect(jsonMax).toBe(bytes(LIMITS.JSON_BODY_LIMIT.replace('mb', 'm')));
    // JSON stays buffered by nginx (the default), with the honest maximum in memory, never spooled responses.
    expect(directive(apiOwn, 'proxy_request_buffering')).toEqual([]);
    expect(directive(apiOwn, 'proxy_buffering')).toEqual([]);
    expect(directive(apiOwn, 'client_body_buffer_size').map(bytes)[0]).toBeGreaterThanOrEqual(
      2 * LIMITS.MAX_ENCRYPTED_MANIFEST_CHARS,
    );
    expect(directive(apiOwn, 'proxy_max_temp_file_size')).toEqual(['0']);
    const [jsonTimeout] = directive(apiOwn, 'client_body_timeout').map(seconds);
    const [chunkTimeout] = directive(chunkOwn, 'client_body_timeout').map(seconds);
    expect(jsonTimeout as number).toBeLessThanOrEqual(15);
    // The chunk backstop must not cut a body before the API's own idle window does (the API then answers itself).
    expect(chunkTimeout as number).toBeGreaterThan(apiDefault('CHUNK_UPLOAD_IDLE_TIMEOUT_SEC'));
  });

  it('the chunk location sends exactly the same headers as /api/ (it declares none of its own)', () => {
    expect(chunkHeader, 'a chunk location nested in /api/').not.toBeNull();
    for (const name of ['add_header', 'proxy_hide_header', 'proxy_set_header']) {
      expect(directive(chunkOwn, name), name).toEqual([]);
      expect(effective(name, chunkOwn), name).toEqual(effective(name, apiOwn));
    }
    expect(effective('add_header', chunkOwn)).toEqual([
      `Strict-Transport-Security "${PRODUCTION_ONLY_HEADERS['Strict-Transport-Security']}" always`,
      `Permissions-Policy "${SECURITY_HEADERS['Permissions-Policy']}" always`,
    ]);
    expect(effective('proxy_hide_header', chunkOwn)).toEqual(['Strict-Transport-Security']);
    // nginx appends the client it resolved, which is what makes TRUST_PROXY=1 right for chunk routes too.
    expect(effective('proxy_set_header', chunkOwn)).toEqual([
      'Host $host',
      'X-Forwarded-For $proxy_add_x_forwarded_for',
      'X-Forwarded-Proto $scheme',
      'Connection ""',
    ]);
  });

  it('bounds slow headers and idle connections, and Caddy drops idle upstream connections first', () => {
    expect(directive(serverOwn, 'client_header_timeout').map(seconds)[0]).toBeLessThanOrEqual(10);
    expect(directive(serverOwn, 'reset_timedout_connection')).toEqual(['on']);
    const [keepalive] = directive(serverOwn, 'keepalive_timeout').map(seconds);
    const caddy = /^\s*keepalive (\d+)s$/m.exec(read('deploy', 'Caddyfile'));
    expect(Number(caddy?.[1])).toBeLessThan(keepalive as number);
  });

  it('trusts X-Forwarded-For from the fixed Caddy address of docker-compose.prod.yml, and only from exact addresses', () => {
    const caddy = service('caddy');
    expect(caddy).toMatch(/\n {4}networks:\n {6}edge:\n {8}ipv4_address: ([\d.]+)\n/);
    const caddyIp = /ipv4_address: ([\d.]+)/.exec(caddy)?.[1] as string;
    const trusted = directive(serverOwn, 'set_real_ip_from');
    expect(trusted).toContain(caddyIp);
    // Exact addresses, never a range: with Docker's userland proxy, direct clients reach nginx from a bridge gateway
    // address, and a range would believe the X-Forwarded-For they send. An operator's own proxy in front of nginx may
    // be listed too, by its exact address (docs/DEPLOYMENT.md, TRUST_PROXY).
    expect(trusted.filter((entry) => isIP(entry) === 0)).toEqual([]);
    // Server level only, so no location replaces or widens the list.
    expect(directive(code, 'set_real_ip_from')).toEqual(trusted);
    expect(directive(serverOwn, 'real_ip_header')).toEqual(['X-Forwarded-For']);
    expect(directive(code, 'real_ip_recursive')).toEqual([]);
    expect(service('web')).toMatch(/networks: \[default, edge\]/);
    const edge = /\n {2}edge:\n[\s\S]*?subnet: (\S+)\n\s+ip_range: (\S+)\n\s+gateway: (\S+)\n/.exec(
      compose,
    );
    const [, subnet, ipRange, gateway] = edge ?? [];
    expect(inCidr(caddyIp, subnet as string)).toBe(true);
    // Dynamic addresses (web) come from ip_range, so they never take Caddy's; the gateway is where direct
    // clients appear from with the userland proxy, so it must never be the trusted address.
    expect(inCidr(caddyIp, ipRange as string)).toBe(false);
    expect(gateway).not.toBe(caddyIp);
    // Caddy is the only proxy on `edge`: its gateway and its dynamic addresses are never a trusted proxy.
    const otherOnEdge = trusted.filter(
      (entry) => entry !== caddyIp && isIP(entry) === 4 && inCidr(entry, subnet as string),
    );
    expect(otherOnEdge).toEqual([]);
  });

  it('sizes every tmpfs of the web container', () => {
    const tmpfs = /\n {4}tmpfs:\n((?: {6}- .*\n)+)/.exec(service('web'))?.[1] ?? '';
    const mounts = [...tmpfs.matchAll(/- (\S+)/g)].map((m) => m[1] as string);
    expect(mounts.map((m) => m.split(':')[0])).toEqual(['/var/cache/nginx', '/var/run', '/tmp']);
    for (const m of mounts) {
      const size = /:size=(\d+[km])$/.exec(m)?.[1];
      expect(size, m).toBeDefined();
      expect(bytes(size as string), m).toBeLessThanOrEqual(64 * 1024 * 1024);
    }
  });
});

/**
 * nginx's text form of an IPv6 address (ngx_inet6_ntop in src/core/ngx_inet.c): the first longest run of two or more
 * zero groups becomes "::", groups have no leading zeros, and ::ffff:a.b.c.d (or ::a.b.c.d) ends in dotted IPv4.
 */
function nginxIpv6Text(bytes: number[]): string {
  const group = (i: number) => (bytes[i] as number) * 256 + (bytes[i + 1] as number);
  let zero = -1;
  let last = -1;
  let max = 1;
  let n = 0;
  for (let i = 0; i < 16; i += 2) {
    if (group(i) !== 0) {
      if (max < n) [zero, max] = [last, n];
      n = 0;
      continue;
    }
    if (n++ === 0) last = i;
  }
  if (max < n) [zero, max] = [last, n];
  let out = '';
  let end = 16;
  if (zero === 0) {
    const mapped = max === 5 && bytes[10] === 0xff && bytes[11] === 0xff;
    if (mapped || max === 6 || (max === 7 && bytes[14] !== 0 && bytes[15] !== 1)) end = 12;
    out += ':';
  }
  for (let i = 0; i < end; i += 2) {
    if (i === zero) {
      out += ':';
      i += (max - 1) * 2;
      continue;
    }
    out += group(i).toString(16);
    if (i < 14) out += ':';
  }
  return end === 12 ? `${out}${bytes.slice(12).join('.')}` : out;
}

describe('deploy/nginx.conf access log (ops-6)', () => {
  const format = /^log_format privacy '([^']*)';/m.exec(httpLevel)?.[1] ?? '';

  it('writes every request this server answers in the privacy format, replacing the image `main` format', () => {
    // At server level, so the http-level `access_log ... main` of the image's nginx.conf is not inherited; none at
    // http level here (two access_log lines on one level would both log).
    expect(directive(serverOwn, 'access_log')).toEqual(['/var/log/nginx/access.log privacy']);
    expect(directive(httpLevel, 'access_log')).toEqual([]);
    // Every other access_log turns logging off for its location; none names another format.
    const all = [...code.matchAll(/(?:^|[;{}])\s*access_log\s+([^;]*);/g)].map((m) => m[1]);
    expect(all.filter((args) => args !== 'off')).toEqual(['/var/log/nginx/access.log privacy']);
  });

  it('logs only the IP prefix, the method, the path without its query string and the outcome', () => {
    expect(format).not.toBe('');
    const variables = [...format.matchAll(/\$(\w+)/g)].map((m) => m[1]);
    expect(variables.sort()).toEqual(
      [
        'time_iso8601',
        'client_prefix',
        'request_method',
        'request_path',
        'status',
        'body_bytes_sent',
        'request_time',
      ].sort(),
    );
    // In particular none of these (full address, request line with query, user agent, referer, proxy chain).
    for (const forbidden of [
      'remote_addr',
      'binary_remote_addr',
      'realip_remote_addr',
      'request',
      'request_uri',
      'uri',
      'args',
      'query_string',
      'http_user_agent',
      'http_referer',
      'http_x_forwarded_for',
      'proxy_add_x_forwarded_for',
    ]) {
      expect(variables, forbidden).not.toContain(forbidden);
    }
  });

  it('logs the path the client asked for, without the query string', () => {
    const map = block(code, 'map $request_uri $request_path');
    const rules = [...map.matchAll(/"~([^"]+)"\s+\$(\w+);/g)];
    expect(rules).toHaveLength(1);
    const [, re, group] = rules[0] as RegExpMatchArray;
    const pathOf = (requestUri: string) =>
      new RegExp(re as string).exec(requestUri)?.groups?.[group as string];
    expect(pathOf('/d/AAAAAAAAAAAAAAAAAAAAAA')).toBe('/d/AAAAAAAAAAAAAAAAAAAAAA');
    expect(pathOf('/api/drops?cursor=abc&limit=10')).toBe('/api/drops');
    expect(pathOf('/SECURITY.md?name=board%20minutes')).toBe('/SECURITY.md');
    expect(pathOf('/?')).toBe('/');
  });

  it('writes the client prefix exactly as the API ipPrefix() does, for every form nginx prints an address in', () => {
    const map = block(code, 'map $remote_addr $client_prefix');
    const rules = [...map.matchAll(/"~(\*?)([^"]+)"\s+(\S+);/g)].map(
      ([, ci, re, value]) => [new RegExp(re as string, ci ? 'i' : ''), value as string] as const,
    );
    const fallback = /default\s+(\S+);/.exec(map)?.[1];
    expect(rules.length).toBeGreaterThan(0);
    // nginx map semantics: the first regex that matches, its value with the named captures substituted.
    const prefixOf = (addr: string): string | undefined => {
      for (const [re, value] of rules) {
        const m = re.exec(addr);
        if (m) return value.replace(/\$(\w+)/g, (_, name: string) => m.groups?.[name] ?? '');
      }
      return fallback;
    };

    // Deterministic pseudo-random addresses (mulberry32), each group zero half of the time, so runs of zero groups
    // of every length and position appear, plus the special forms.
    let seed = 0x5eed;
    const next = (bound: number) => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) % bound;
    };
    const v6: number[][] = [
      Array(16).fill(0),
      [...Array(15).fill(0), 1],
      [...Array(10).fill(0), 0xff, 0xff, 198, 51, 100, 7],
      [...Array(12).fill(0), 1, 2, 3, 4],
      [0x20, 0x01, 0x0d, 0xb8, ...Array(11).fill(0), 1],
    ];
    for (let i = 0; i < 4000; i++) {
      v6.push(
        Array.from({ length: 8 }).flatMap(() => {
          const g = next(2) === 0 ? 0 : next(2) === 0 ? next(16) : next(65536);
          return [g >> 8, g & 0xff];
        }),
      );
    }
    const addrs = [
      ...v6.map(nginxIpv6Text),
      '198.51.100.7',
      '10.0.0.1',
      '0.0.0.0',
      ...Array.from({ length: 200 }, () => [next(256), next(256), next(256), next(256)].join('.')),
    ];
    // The forms the special cases are about, as nginx prints them.
    expect(addrs).toEqual(
      expect.arrayContaining(['::', '::1', '::ffff:198.51.100.7', '::1.2.3.4', '2001:db8::1']),
    );
    for (const addr of addrs) {
      // The API sees the same text: nginx forwards $remote_addr in X-Forwarded-For.
      expect(prefixOf(addr), addr).toBe(ipPrefix(addr));
    }
    expect(prefixOf('unix:')).toBe('-');
  });
});

describe('deploy/nginx.conf /.well-known/ (docs-9)', () => {
  it('serves the built security.txt as UTF-8 plain text, never the SPA, with the inherited headers', () => {
    const body = block(server, 'location = /.well-known/security.txt');
    const own = ownLevel(body);
    // An empty types map: every file here is text/plain, whatever its extension.
    expect(body).toMatch(/^\s*types \{ \}$/m);
    expect(directive(own, 'default_type')).toEqual(['text/plain']);
    expect(directive(own, 'charset')).toEqual(['utf-8']);
    expect(directive(own, 'try_files')).toEqual(['$uri =404']);
    expect(directive(own, 'add_header')).toEqual([]);
  });

  it('answers every other /.well-known/ path with a 404, ahead of the regex locations', () => {
    const own = ownLevel(block(server, 'location ^~ /.well-known/'));
    expect(directive(own, 'return')).toEqual(['404']);
    expect(directive(own, 'add_header')).toEqual([]);
  });
});

describe('docker-compose.prod.yml isolation and limits (ops-7)', () => {
  // The top-level keys of `services:` (the block before `networks:`).
  const servicesBlock = compose.slice(
    compose.indexOf('\nservices:\n'),
    compose.indexOf('\nnetworks:\n'),
  );
  const services = [...servicesBlock.matchAll(/^ {2}([a-z][a-z0-9-]*):\n/gm)].map(
    (m) => m[1] as string,
  );
  const networksOf = (name: string) =>
    /\n {4}networks: \[([^\]]*)\]\n/.exec(`\n${service(name)}`)?.[1]?.split(/,\s*/) ?? [];

  it('lists the services it checks', () => {
    expect(services.sort()).toEqual(
      ['api', 'caddy', 'migrate', 'minio', 'postgres', 'redis', 'web'].sort(),
    );
  });

  it('keeps Postgres, Redis and MinIO on the internal backend network, which only the API and migrate join', () => {
    expect(compose).toMatch(/\nnetworks:\n(?: {2}#.*\n)* {2}backend:\n {4}internal: true\n/);
    for (const name of ['postgres', 'redis', 'minio', 'migrate']) {
      expect(networksOf(name), name).toEqual(['backend']);
    }
    expect(networksOf('api')).toEqual(['default', 'backend']);
    expect(networksOf('web')).toEqual(['default', 'edge']);
    // Caddy has its own network block (a fixed address on edge, checked above), and nothing on backend.
    expect(service('caddy')).not.toMatch(/backend/);
    const onBackend = services.filter((name) => networksOf(name).includes('backend'));
    expect(onBackend.sort()).toEqual(['api', 'migrate', 'minio', 'postgres', 'redis'].sort());
  });

  it('gives every service a memory and a pids limit', () => {
    for (const name of services) {
      const own = service(name);
      expect(own, name).toMatch(/\n {4}mem_limit: \d+[mg]\n/);
      expect(own, name).toMatch(/\n {4}pids_limit: \d+\n/);
    }
  });

  it('protects Redis with a password that the API and the healthcheck use, and never evicts keys', () => {
    const redis = service('redis');
    expect(redis).toMatch(/REDISCLI_AUTH: \$\{REDIS_PASSWORD:\?[^}]+\}/);
    expect(redis).toMatch(/--requirepass "\$\$REDISCLI_AUTH"/);
    // A redis-server command, so that the image's entrypoint still drops root.
    expect(redis).toMatch(/exec docker-entrypoint\.sh redis-server /);
    expect(redis).toMatch(/--maxmemory-policy noeviction/);
    expect(redis).toMatch(/test: \['CMD-SHELL', 'redis-cli ping \| grep -qx PONG'\]/);
    expect(service('api')).toMatch(
      /REDIS_URL: redis:\/\/:\$\{REDIS_PASSWORD:\?[^}]+\}@redis:6379\/0/,
    );
  });

  it('runs migrations in a one-shot service as the owner, and the API as the runtime role after it', () => {
    const migrate = service('migrate');
    const api = service('api');
    expect(migrate).toMatch(/command: \['migrate'\]/);
    expect(migrate).toMatch(/dockerfile: apps\/api\/Dockerfile/);
    expect(migrate).toMatch(/DATABASE_URL: postgresql:\/\/cipherdrop:\$\{POSTGRES_PASSWORD\}@/);
    expect(migrate).toMatch(/DB_RUNTIME_ROLE: cipherdrop_app\n/);
    expect(migrate).toMatch(/restart: 'no'/);
    expect(api).toMatch(/DATABASE_URL: postgresql:\/\/cipherdrop_app:\$\{POSTGRES_APP_PASSWORD:\?/);
    expect(api).toMatch(/MIGRATE_ON_START: 'false'/);
    expect(api).toMatch(/POSTGRES_PASSWORD: ''/);
    expect(api).toMatch(
      /depends_on:\n {6}migrate:\n {8}condition: service_completed_successfully\n/,
    );
    const entrypoint = read('deploy', 'api-entrypoint.sh');
    expect(entrypoint).toMatch(/\n {2}migrate\)\n {4}migrate\n/);
    expect(entrypoint).toMatch(
      /if \[ "\$\{MIGRATE_ON_START:-true\}" != false \]; then migrate; fi/,
    );
  });
});
