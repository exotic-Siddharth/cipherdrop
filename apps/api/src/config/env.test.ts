/**
 * parseEnv production guard (C-11): a production process refuses insecure or dev-default configuration
 * instead of starting with it silently. Development and test keep their defaults.
 */
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEnv } from './env';

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
      });
    }
  });
});
