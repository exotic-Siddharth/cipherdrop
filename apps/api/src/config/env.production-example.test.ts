/**
 * The shipped .env.production.example against the production guard (C-11): the template as it stands must be
 * REFUSED (its secrets are placeholders), and once the placeholders are replaced with real values the API must
 * accept it. docker-compose.prod.yml adds the topology values (DATABASE_URL, REDIS_URL, NODE_ENV, STORAGE_DIR): the
 * api service's `environment:` is read from the compose file and interpolated from the env file, as compose does.
 * The one-shot `migrate` service gets the owner's URL and the runtime role's password instead; its own checks
 * (db/runtimeRole.ts) must refuse the template's placeholders there.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { checkOwnerUrl, checkRuntimeRoleOptions } from '../db/runtimeRole';
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
const compose = readFileSync(path.join(path.dirname(file), 'docker-compose.prod.yml'), 'utf8');

/**
 * The `environment:` of a docker-compose.prod.yml service, interpolated from the env file `values` as compose does
 * (${X}, ${X:-default}, ${X:?message}).
 */
function environmentLayer(service: string, values: Record<string, string>): Record<string, string> {
  const own = new RegExp(`^ {2}${service}:\\n((?:(?: {4}.*)?\\n)*)`, 'm').exec(compose)?.[1] ?? '';
  const block = /^ {4}environment:\n((?: {6}.*\n)*)/m.exec(own)?.[1] ?? '';
  const layer: Record<string, string> = {};
  for (const [, key, raw] of block.matchAll(/^ {6}([A-Z][A-Z0-9_]*): (.*)$/gm)) {
    const unquoted = (raw as string).trim().replace(/^'(.*)'$/, '$1');
    layer[key as string] = unquoted.replace(
      /\$\{([A-Z][A-Z0-9_]*)(?::([?-])([^}]*))?\}/g,
      (_, name: string, op?: string, arg?: string) => {
        const v = values[name];
        if (v !== undefined && v !== '') return v;
        if (op === '?') throw new Error(`compose refuses to start: ${arg}`);
        return op === '-' ? (arg ?? '') : '';
      },
    );
  }
  return layer;
}

/**
 * The api container's environment as docker-compose.prod.yml builds it from the env file `values`: env_file passes
 * them all, and its `environment:` takes precedence.
 */
function apiEnvironment(values: Record<string, string>): Record<string, string> {
  const layer = environmentLayer('api', values);
  expect(Object.keys(layer)).toEqual(expect.arrayContaining(['DATABASE_URL', 'REDIS_URL']));
  return { ...values, ...layer };
}

/** The `migrate` container's environment: its `environment:` only (it has no env_file). */
function migrateEnvironment(values: Record<string, string>): Record<string, string> {
  expect(compose).not.toMatch(/^ {2}migrate:\n(?: {4}.*\n)*? {4}env_file:/m);
  const layer = environmentLayer('migrate', values);
  expect(Object.keys(layer).sort()).toEqual(
    ['DATABASE_URL', 'DB_RUNTIME_PASSWORD', 'DB_RUNTIME_ROLE'].sort(),
  );
  return layer;
}

/** What the `migrate` one-shot checks before it touches the runtime role (db/provision-runtime-role.ts). */
function migrateChecks(env: Record<string, string>): void {
  checkOwnerUrl(env.DATABASE_URL);
  checkRuntimeRoleOptions({
    role: env.DB_RUNTIME_ROLE ?? '',
    password: env.DB_RUNTIME_PASSWORD ?? '',
    schema: new URL(env.DATABASE_URL ?? '').searchParams.get('schema') ?? 'public',
  });
}

/** Every REQUIRED placeholder replaced with a generated value, as the file tells the operator to. */
const filledValues = (): Record<string, string> => ({
  ...template,
  POSTGRES_PASSWORD: randomBytes(24).toString('hex'),
  POSTGRES_APP_PASSWORD: randomBytes(24).toString('hex'),
  REDIS_PASSWORD: randomBytes(32).toString('hex'),
  JWT_ACCESS_SECRET: randomBytes(32).toString('hex'),
  PRELOGIN_SECRET: randomBytes(32).toString('hex'),
  TOTP_ENC_KEY: randomBytes(32).toString('base64'),
});
const filled = () => apiEnvironment(filledValues());

describe('.env.production.example', () => {
  it('is refused as shipped: every secret and connection password is still a placeholder', () => {
    const attempt = () => parseEnv(apiEnvironment(template));
    expect(attempt).toThrow(/JWT_ACCESS_SECRET/);
    expect(attempt).toThrow(/PRELOGIN_SECRET/);
    expect(attempt).toThrow(/TOTP_ENC_KEY/);
    expect(attempt).toThrow(/DATABASE_URL: its password is a development\/test placeholder/);
    expect(attempt).toThrow(/REDIS_URL: its password is a development\/test placeholder/);
  });

  it('is refused by the migrate one-shot as shipped: the owner and the runtime role passwords are placeholders', () => {
    const shipped = migrateEnvironment(template);
    expect(() => migrateChecks(shipped)).toThrow(
      /DATABASE_URL: the owner password is still a placeholder/,
    );
    // With only the owner password filled in, the runtime role's placeholder is refused next.
    const ownerOnly = migrateEnvironment({
      ...template,
      POSTGRES_PASSWORD: randomBytes(24).toString('hex'),
    });
    expect(() => migrateChecks(ownerOnly)).toThrow(/DB_RUNTIME_PASSWORD is still a placeholder/);
    // ...and with only the two new passwords filled in, the owner's (the superuser's) is still refused.
    const ownerForgotten = migrateEnvironment({
      ...template,
      POSTGRES_APP_PASSWORD: randomBytes(24).toString('hex'),
      REDIS_PASSWORD: randomBytes(32).toString('hex'),
    });
    expect(() => migrateChecks(ownerForgotten)).toThrow(/DATABASE_URL/);
    // Filled in, it passes: the owner's URL with POSTGRES_PASSWORD, the runtime role with POSTGRES_APP_PASSWORD.
    const values = filledValues();
    const env = migrateEnvironment(values);
    expect(() => migrateChecks(env)).not.toThrow();
    expect(new URL(env.DATABASE_URL ?? '').password).toBe(values.POSTGRES_PASSWORD);
    expect(env.DB_RUNTIME_PASSWORD).toBe(values.POSTGRES_APP_PASSWORD);
  });

  it('gives the API the runtime role and the Redis password, never the database owner password (ops-7)', () => {
    const values = filledValues();
    const env = parseEnv(apiEnvironment(values));
    const db = new URL(env.DATABASE_URL);
    expect(db.username).toBe('cipherdrop_app');
    expect(db.password).toBe(values.POSTGRES_APP_PASSWORD);
    expect(new URL(env.REDIS_URL).password).toBe(values.REDIS_PASSWORD);
    const container = apiEnvironment(values);
    expect(container.POSTGRES_PASSWORD).toBe('');
    expect(Object.values(container)).not.toContain(values.POSTGRES_PASSWORD);
    expect(container.MIGRATE_ON_START).toBe('false');
    // Compose refuses to start without the two passwords instead of using an empty one.
    for (const key of ['POSTGRES_APP_PASSWORD', 'REDIS_PASSWORD']) {
      expect(() => apiEnvironment({ ...values, [key]: '' })).toThrow(new RegExp(key));
    }
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
    const consumedByCompose = [
      'POSTGRES_PASSWORD',
      'POSTGRES_APP_PASSWORD',
      'REDIS_PASSWORD',
      'WEB_BIND',
      'WEB_PORT',
      'SITE_ADDRESS',
    ];
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
