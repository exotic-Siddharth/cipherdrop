/**
 * parseEnv production guard (C-11): a production process refuses insecure or dev-default configuration
 * instead of starting with it silently. Development and test keep their defaults.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseEnv } from './env';
import { apiRoot } from './paths';

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

  it('requires TRUST_PROXY to be stated (0 is the explicit "no proxy" opt-out)', () => {
    expect(() => parseEnv(without('TRUST_PROXY'))).toThrow(/TRUST_PROXY/);
    expect(parseEnv({ ...prod(), TRUST_PROXY: '0' }).TRUST_PROXY).toBe(0);
    expect(parseEnv({ ...prod(), TRUST_PROXY: '2' }).TRUST_PROXY).toBe(2);
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

  it('keeps the local defaults in development and test', () => {
    for (const NODE_ENV of ['development', 'test']) {
      const env = parseEnv({ ...dev, NODE_ENV });
      expect(env).toMatchObject({
        COOKIE_SECURE: false,
        TRUST_PROXY: 0,
        WEB_ORIGIN: 'http://localhost:5174',
      });
    }
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
