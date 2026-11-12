/**
 * The shipped .env.production.example against the production guard (C-11): the template as it stands must be
 * REFUSED (its secrets are placeholders), and once the placeholders are replaced with real values the API must
 * accept it. docker-compose.prod.yml adds the topology values (DATABASE_URL, REDIS_URL, NODE_ENV, STORAGE_DIR).
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseEnv } from './env';

const file = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  '..',
  '.env.production.example',
);

/** KEY=value lines only (no quotes, as documented in the file). */
function parseDotenv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (m) out[m[1] as string] = (m[2] as string).trim();
  }
  return out;
}

const template = parseDotenv(readFileSync(file, 'utf8'));

/** What docker-compose.prod.yml layers over the env file for the api container. */
const composeLayer = {
  NODE_ENV: 'production',
  API_PORT: '4100',
  DATABASE_URL: `postgresql://cipherdrop:${randomBytes(12).toString('hex')}@postgres:5432/cipherdrop?schema=public`,
  REDIS_URL: 'redis://redis:6379/0',
  STORAGE_DIR: '/data/blobs',
};

const filled = (): Record<string, string> => ({
  ...template,
  ...composeLayer,
  JWT_ACCESS_SECRET: randomBytes(32).toString('hex'),
  PRELOGIN_SECRET: randomBytes(32).toString('hex'),
  TOTP_ENC_KEY: randomBytes(32).toString('base64'),
});

describe('.env.production.example', () => {
  it('is refused as shipped: every secret is still a placeholder', () => {
    const attempt = () => parseEnv({ ...template, ...composeLayer });
    expect(attempt).toThrow(/JWT_ACCESS_SECRET/);
    expect(attempt).toThrow(/PRELOGIN_SECRET/);
    expect(attempt).toThrow(/TOTP_ENC_KEY/);
  });

  it('is accepted by the production guard once the placeholders are filled in', () => {
    const env = parseEnv(filled());
    expect(env).toMatchObject({
      NODE_ENV: 'production',
      COOKIE_SECURE: true,
      TRUST_PROXY: 1,
      STORAGE_DRIVER: 'local',
      WEB_ORIGIN: 'https://drop.example.com',
      RATE_LIMITS_ENABLED: true,
    });
  });

  it('still depends on COOKIE_SECURE and a bare-origin WEB_ORIGIN (the guard is not bypassed by the file)', () => {
    expect(() => parseEnv({ ...filled(), COOKIE_SECURE: 'false' })).toThrow(/COOKIE_SECURE/);
    expect(() => parseEnv({ ...filled(), WEB_ORIGIN: 'https://drop.example.com/' })).toThrow(
      /WEB_ORIGIN/,
    );
  });

  it('every variable it sets is one the API reads or the compose file consumes', () => {
    const consumedByCompose = ['POSTGRES_PASSWORD', 'WEB_BIND', 'WEB_PORT', 'SITE_ADDRESS'];
    const envSource = readFileSync(
      path.join(path.dirname(file), 'apps/api/src/config/env.ts'),
      'utf8',
    );
    for (const key of Object.keys(template)) {
      if (consumedByCompose.includes(key)) continue;
      expect(envSource, `${key} is not an API variable`).toContain(`${key}:`);
    }
  });
});
