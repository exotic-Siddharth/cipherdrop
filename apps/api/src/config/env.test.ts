/**
 * parseEnv production guard (C-11): a production process refuses insecure or dev-default configuration
 * instead of starting with it silently. Development and test keep their defaults.
 */
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEnv } from './env';

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
