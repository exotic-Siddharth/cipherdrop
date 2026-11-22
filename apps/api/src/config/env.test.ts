/**
 * parseEnv production guard (C-11): a production process refuses insecure or dev-default configuration
 * instead of starting with it silently. Development and test keep their defaults.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ENV_KEYS, parseEnv } from './env';
import { apiRoot } from './paths';

const MiB = 1024 * 1024;

const prod = (): Record<string, string> => ({
  NODE_ENV: 'production',
  JWT_ACCESS_SECRET: randomBytes(32).toString('base64url'),
  PRELOGIN_SECRET: randomBytes(32).toString('base64url'),
  TOTP_ENC_KEY: randomBytes(32).toString('base64'),
  COOKIE_SECURE: 'true',
  DATABASE_URL: 'postgresql://app:s3cret@db.internal:5432/cipherdrop?schema=public',
  REDIS_URL: 'redis://cache.internal:6379/0',
  WEB_ORIGIN: 'https://drop.example',
  TRUST_PROXY: '1',
});

const without = (key: string): Record<string, string> => {
  const src = prod();
  delete src[key];
  return src;
};

describe('parseEnv in production', () => {
  it('accepts a complete, explicit configuration', () => {
    const env = parseEnv(prod());
    expect(env).toMatchObject({
      COOKIE_SECURE: true,
      TRUST_PROXY: 1,
      WEB_ORIGIN: 'https://drop.example',
    });
  });

  it('requires COOKIE_SECURE=true', () => {
    expect(() => parseEnv({ ...prod(), COOKIE_SECURE: 'false' })).toThrow(/COOKIE_SECURE/);
    expect(() => parseEnv(without('COOKIE_SECURE'))).toThrow(/COOKIE_SECURE/);
  });

  it.each(['DATABASE_URL', 'REDIS_URL', 'WEB_ORIGIN'])(
    'requires %s to be set explicitly (no dev default)',
    (key) => {
      expect(() => parseEnv(without(key))).toThrow(new RegExp(key));
      expect(() => parseEnv({ ...prod(), [key]: '' })).toThrow(new RegExp(key));
    },
  );

  it('requires WEB_ORIGIN to be a bare origin (no path or trailing slash)', () => {
    expect(() => parseEnv({ ...prod(), WEB_ORIGIN: 'https://drop.example/' })).toThrow(
      /WEB_ORIGIN/,
    );
    expect(() => parseEnv({ ...prod(), WEB_ORIGIN: 'https://drop.example/app' })).toThrow(
      /WEB_ORIGIN/,
    );
    expect(parseEnv({ ...prod(), WEB_ORIGIN: 'https://drop.example:8443' }).WEB_ORIGIN).toBe(
      'https://drop.example:8443',
    );
  });

  it('refuses API_DOCS_UI=true: Swagger UI never runs on the origin that holds the keys', () => {
    expect(() => parseEnv({ ...prod(), API_DOCS_UI: 'true' })).toThrow(/API_DOCS_UI/);
    expect(parseEnv(prod()).API_DOCS_UI).toBe(false);
    expect(parseEnv({ ...prod(), API_DOCS_UI: 'false' }).API_DOCS_UI).toBe(false);
  });

  it('requires TRUST_PROXY to be stated (0 is the explicit "no proxy" opt-out)', () => {
    expect(() => parseEnv(without('TRUST_PROXY'))).toThrow(/TRUST_PROXY/);
    expect(parseEnv({ ...prod(), TRUST_PROXY: '0' }).TRUST_PROXY).toBe(0);
    expect(parseEnv({ ...prod(), TRUST_PROXY: '2' }).TRUST_PROXY).toBe(2);
  });

  it('refuses a placeholder password in DATABASE_URL or REDIS_URL, and never prints it', () => {
    const placeholder = 'change-me-generate-with-openssl-rand-hex-32';
    for (const [key, url] of [
      ['DATABASE_URL', `postgresql://app:${placeholder}@db.internal:5432/cipherdrop?schema=public`],
      ['REDIS_URL', `redis://:${placeholder}@cache.internal:6379/0`],
      ['REDIS_URL', `redis://default:${encodeURIComponent('Dev-Only pw')}@cache.internal:6379/0`],
    ] as const) {
      let message = '';
      try {
        parseEnv({ ...prod(), [key]: url });
      } catch (err) {
        message = (err as Error).message;
      }
      expect(message).toContain(`${key}: its password is a development/test placeholder`);
      expect(message).not.toContain(placeholder);
    }
    // A real password, or none (a Redis on a private socket), is fine.
    const pw = randomBytes(32).toString('hex');
    expect(
      parseEnv({ ...prod(), REDIS_URL: `redis://:${pw}@cache.internal:6379/0` }).REDIS_URL,
    ).toContain(pw);
    expect(() => parseEnv({ ...prod(), REDIS_URL: 'redis://cache.internal:6379/0' })).not.toThrow();
  });

  it('reports every problem at once, names only, never values', () => {
    let message = '';
    try {
      parseEnv({ NODE_ENV: 'production', JWT_ACCESS_SECRET: 'x'.repeat(40) + 'SECRETVALUE' });
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain('TOTP_ENC_KEY');
    expect(message).toContain('TRUST_PROXY');
    expect(message).toContain('DATABASE_URL');
    expect(message).not.toContain('SECRETVALUE');
  });
});

describe('parseEnv outside production', () => {
  const dev = {
    JWT_ACCESS_SECRET: 'dev-only-jwt-access-secret-0123456789abcdef',
    PRELOGIN_SECRET: 'dev-only-prelogin-hmac-secret-0123456789abcdef',
    TOTP_ENC_KEY: Buffer.alloc(32, 7).toString('base64'),
  };

  it('S3_DELETE_ALL_VERSIONS is off unless set, and only takes a boolean (critic-4)', () => {
    expect(parseEnv({ ...dev, NODE_ENV: 'development' }).S3_DELETE_ALL_VERSIONS).toBe(false);
    expect(parseEnv({ ...dev, S3_DELETE_ALL_VERSIONS: 'true' }).S3_DELETE_ALL_VERSIONS).toBe(true);
    expect(() => parseEnv({ ...dev, S3_DELETE_ALL_VERSIONS: 'versions' })).toThrow(
      /S3_DELETE_ALL_VERSIONS/,
    );
  });

  it('caps anonymous storage by default (10 GiB); 0 is the explicit "no ceiling" opt-out', () => {
    expect(parseEnv(dev).ANON_TOTAL_PENDING_BYTES).toBe(10 * 1024 ** 3);
    expect(parseEnv({ ...dev, ANON_TOTAL_PENDING_BYTES: '0' }).ANON_TOTAL_PENDING_BYTES).toBe(0);
    expect(() => parseEnv({ ...dev, ANON_TOTAL_PENDING_BYTES: '-1' })).toThrow(
      /ANON_TOTAL_PENDING_BYTES/,
    );
  });

  it('meters anonymous bytes per client by default (1 GiB per 24 h); 0 turns it off', () => {
    expect(parseEnv(dev)).toMatchObject({
      ANON_BYTES_PER_CLIENT: 1024 ** 3,
      ANON_BYTES_WINDOW_HOURS: 24,
    });
    expect(parseEnv({ ...dev, ANON_BYTES_PER_CLIENT: '0' }).ANON_BYTES_PER_CLIENT).toBe(0);
    expect(() => parseEnv({ ...dev, ANON_BYTES_WINDOW_HOURS: '0' })).toThrow(
      /ANON_BYTES_WINDOW_HOURS/,
    );
  });

  it('refuses a per-client budget below the largest anonymous drop (it could never be sent)', () => {
    expect(() =>
      parseEnv({ ...dev, ANON_MAX_DROP_BYTES: '1000', ANON_BYTES_PER_CLIENT: '999' }),
    ).toThrow(/ANON_BYTES_PER_CLIENT: .*together with ANON_MAX_DROP_BYTES/);
    // The budget counts whole MiB, so a 1000-byte drop takes 1 MiB of it.
    expect(() =>
      parseEnv({ ...dev, ANON_MAX_DROP_BYTES: '1000', ANON_BYTES_PER_CLIENT: String(MiB - 1) }),
    ).toThrow(/ANON_BYTES_PER_CLIENT/);
    expect(
      parseEnv({ ...dev, ANON_MAX_DROP_BYTES: '1000', ANON_BYTES_PER_CLIENT: String(MiB) })
        .ANON_BYTES_PER_CLIENT,
    ).toBe(MiB);
    // The upgrade case: a larger ANON_MAX_DROP_BYTES with the default budget is refused at boot.
    expect(() => parseEnv({ ...dev, ANON_MAX_DROP_BYTES: String(2 * 1024 * MiB) })).toThrow(
      /ANON_BYTES_PER_CLIENT/,
    );
  });

  it('puts new accounts on probation by default (256 MiB for 7 days); 0 days turns it off', () => {
    expect(parseEnv(dev)).toMatchObject({
      NEW_ACCOUNT_QUOTA_BYTES: 256 * 1024 ** 2,
      NEW_ACCOUNT_PROBATION_DAYS: 7,
    });
    expect(parseEnv({ ...dev, NEW_ACCOUNT_PROBATION_DAYS: '0' }).NEW_ACCOUNT_PROBATION_DAYS).toBe(
      0,
    );
    expect(() => parseEnv({ ...dev, NEW_ACCOUNT_PROBATION_DAYS: '366' })).toThrow(
      /NEW_ACCOUNT_PROBATION_DAYS/,
    );
  });

  it('holds the evidence of a keyed open report for 14 days by default (0 = no hold, at most 90)', () => {
    expect(parseEnv(dev).REPORT_EVIDENCE_HOLD_DAYS).toBe(14);
    expect(parseEnv({ ...dev, REPORT_EVIDENCE_HOLD_DAYS: '0' }).REPORT_EVIDENCE_HOLD_DAYS).toBe(0);
    expect(() => parseEnv({ ...dev, REPORT_EVIDENCE_HOLD_DAYS: '91' })).toThrow(
      /REPORT_EVIDENCE_HOLD_DAYS/,
    );
  });

  it('allows anonymous uploads and registration unless an operator switches them off', () => {
    expect(parseEnv(dev)).toMatchObject({
      ALLOW_ANONYMOUS_UPLOADS: true,
      ALLOW_REGISTRATION: true,
    });
    expect(
      parseEnv({ ...dev, ALLOW_ANONYMOUS_UPLOADS: 'false', ALLOW_REGISTRATION: 'off' }),
    ).toMatchObject({ ALLOW_ANONYMOUS_UPLOADS: false, ALLOW_REGISTRATION: false });
    expect(() => parseEnv({ ...dev, ALLOW_REGISTRATION: 'maybe' })).toThrow(/ALLOW_REGISTRATION/);
  });

  it('ships no global storage cap and a 1 GiB free-disk floor; both accept 0 (off)', () => {
    expect(parseEnv(dev)).toMatchObject({
      GLOBAL_STORAGE_CAP_BYTES: 0,
      STORAGE_MIN_FREE_BYTES: 1024 ** 3,
    });
    expect(
      parseEnv({ ...dev, GLOBAL_STORAGE_CAP_BYTES: '5000', STORAGE_MIN_FREE_BYTES: '0' }),
    ).toMatchObject({ GLOBAL_STORAGE_CAP_BYTES: 5000, STORAGE_MIN_FREE_BYTES: 0 });
    expect(() => parseEnv({ ...dev, GLOBAL_STORAGE_CAP_BYTES: '-1' })).toThrow(
      /GLOBAL_STORAGE_CAP_BYTES/,
    );
  });

  it('keeps the local defaults in development and test', () => {
    for (const NODE_ENV of ['development', 'test']) {
      const env = parseEnv({ ...dev, NODE_ENV });
      expect(env).toMatchObject({
        COOKIE_SECURE: false,
        TRUST_PROXY: 0,
        WEB_ORIGIN: 'http://localhost:5174',
        API_DOCS_UI: false,
      });
    }
  });

  it('serves Swagger UI only when API_DOCS_UI is turned on (the dev .env.example does)', () => {
    expect(parseEnv({ ...dev, NODE_ENV: 'development', API_DOCS_UI: 'true' }).API_DOCS_UI).toBe(
      true,
    );
    expect(parseEnv({ ...dev, NODE_ENV: 'development', API_DOCS_UI: 'off' }).API_DOCS_UI).toBe(
      false,
    );
    expect(() => parseEnv({ ...dev, NODE_ENV: 'development', API_DOCS_UI: 'maybe' })).toThrow(
      /API_DOCS_UI/,
    );
  });
});

describe('Argon2id limiter settings (critic-1)', () => {
  const dev = {
    JWT_ACCESS_SECRET: 'dev-only-jwt-access-secret-0123456789abcdef',
    PRELOGIN_SECRET: 'dev-only-prelogin-hmac-secret-0123456789abcdef',
    TOTP_ENC_KEY: Buffer.alloc(32, 7).toString('base64'),
  };

  it('defaults: 2 concurrent hashes, 32 waiting, below the libuv default pool of 4', () => {
    expect(parseEnv(dev)).toMatchObject({
      ARGON2_MAX_CONCURRENT: 2,
      ARGON2_MAX_QUEUE: 32,
      UV_THREADPOOL_SIZE: 4,
    });
    expect(parseEnv(prod())).toMatchObject({ ARGON2_MAX_CONCURRENT: 2, UV_THREADPOOL_SIZE: 4 });
  });

  it('refuses a cap that could take every libuv thread from file I/O, in every environment', () => {
    expect(() => parseEnv({ ...dev, ARGON2_MAX_CONCURRENT: '4' })).toThrow(/ARGON2_MAX_CONCURRENT/);
    expect(() =>
      parseEnv({ ...prod(), ARGON2_MAX_CONCURRENT: '8', UV_THREADPOOL_SIZE: '8' }),
    ).toThrow(/ARGON2_MAX_CONCURRENT/);
    expect(
      parseEnv({ ...prod(), ARGON2_MAX_CONCURRENT: '4', UV_THREADPOOL_SIZE: '8' }),
    ).toMatchObject({ ARGON2_MAX_CONCURRENT: 4, UV_THREADPOOL_SIZE: 8 });
  });

  it('accepts the API image setting (UV_THREADPOOL_SIZE=8 in apps/api/Dockerfile)', () => {
    const dockerfile = readFileSync(path.join(apiRoot, 'Dockerfile'), 'utf8');
    const size = /UV_THREADPOOL_SIZE=(\d+)/.exec(dockerfile)?.[1];
    expect(size).toBe('8');
    expect(parseEnv({ ...prod(), UV_THREADPOOL_SIZE: size }).UV_THREADPOOL_SIZE).toBe(8);
  });
});

describe('session lifetime settings (server-3)', () => {
  it('defaults to an absolute lifetime of 30 days, the same as the idle limit', () => {
    expect(parseEnv(prod())).toMatchObject({
      REFRESH_TOKEN_TTL_DAYS: 30,
      SESSION_MAX_LIFETIME_DAYS: 30,
    });
  });

  it('defaults the per-grant byte budget to 3x the drop size and bounds it (1 to 100)', () => {
    expect(parseEnv(prod()).DOWNLOAD_GRANT_BYTE_FACTOR).toBe(3);
    expect(() => parseEnv({ ...prod(), DOWNLOAD_GRANT_BYTE_FACTOR: '0' })).toThrow(
      /DOWNLOAD_GRANT_BYTE_FACTOR/,
    );
  });

  it('defaults the admin step-up window to 15 minutes and bounds it (1 to 1440)', () => {
    expect(parseEnv(prod()).ADMIN_STEP_UP_MINUTES).toBe(15);
    expect(parseEnv({ ...prod(), ADMIN_STEP_UP_MINUTES: '5' }).ADMIN_STEP_UP_MINUTES).toBe(5);
    expect(() => parseEnv({ ...prod(), ADMIN_STEP_UP_MINUTES: '0' })).toThrow(
      /ADMIN_STEP_UP_MINUTES/,
    );
    expect(() => parseEnv({ ...prod(), ADMIN_STEP_UP_MINUTES: '1441' })).toThrow(
      /ADMIN_STEP_UP_MINUTES/,
    );
  });

  it('refuses an absolute lifetime shorter than the idle one, in every environment', () => {
    expect(() => parseEnv({ ...prod(), SESSION_MAX_LIFETIME_DAYS: '7' })).toThrow(
      /SESSION_MAX_LIFETIME_DAYS/,
    );
    expect(() =>
      parseEnv({ ...prod(), NODE_ENV: 'development', REFRESH_TOKEN_TTL_DAYS: '60' }),
    ).toThrow(/SESSION_MAX_LIFETIME_DAYS/);
    expect(
      parseEnv({ ...prod(), REFRESH_TOKEN_TTL_DAYS: '7', SESSION_MAX_LIFETIME_DAYS: '90' }),
    ).toMatchObject({ REFRESH_TOKEN_TTL_DAYS: 7, SESSION_MAX_LIFETIME_DAYS: 90 });
  });
});

describe('.env.example at the repo root (the documentation copy of every variable)', () => {
  const repoRoot = path.resolve(apiRoot, '..', '..');
  /** KEY=value lines, and the commented-out `# KEY=value` ones. */
  const keys = (file: string) => {
    const lines = readFileSync(path.join(repoRoot, file), 'utf8').split('\n');
    const pick = (re: RegExp) => new Set(lines.flatMap((line) => re.exec(line)?.slice(1, 2) ?? []));
    return { set: pick(/^([A-Z][A-Z0-9_]*)=/), commented: pick(/^# ([A-Z][A-Z0-9_]*)=/) };
  };
  const copy = keys('.env.example');
  /** libuv reads it from the process environment at start-up only, so the copy shows it commented out. */
  const commentedOnly: readonly string[] = ['UV_THREADPOOL_SIZE'];

  it('lists every variable the API reads, so it cannot drift from env.ts', () => {
    expect(ENV_KEYS).toEqual(expect.arrayContaining(Object.keys(parseEnv(prod()))));
    const missing = ENV_KEYS.filter(
      (key) => !(commentedOnly.includes(key) ? copy.commented : copy.set).has(key),
    );
    expect(missing).toEqual([]);
  });

  it('names only variables of the API or of the web build (apps/web/.env.example)', () => {
    const web = keys('apps/web/.env.example');
    const known = new Set<string>([...ENV_KEYS, ...web.set, ...web.commented]);
    expect([...copy.set, ...copy.commented].filter((key) => !known.has(key))).toEqual([]);
  });
});
