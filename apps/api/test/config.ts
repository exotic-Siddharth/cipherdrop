/**
 * Test isolation settings (R2). Tests NEVER touch the dev database `cipherdrop`:
 * - database `cipherdrop_test` (created by the global setup), schema TEST_SCHEMA (default `test`; lanes use `lane_<id>`);
 * - Redis DB TEST_REDIS_DB (default 15; lanes b1 -> 1, b2 -> 2, e2e -> 9) and a unique KEY_PREFIX per test file.
 *
 * Overrides for other hosts (e.g. CI services): TEST_PG_URL (server URL without database) and TEST_REDIS_BASE_URL.
 */
export const TEST_DB_NAME = 'cipherdrop_test';

const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

export function testSchema(): string {
  const schema = process.env.TEST_SCHEMA?.trim() || 'test';
  if (!SCHEMA_RE.test(schema)) {
    throw new Error(`TEST_SCHEMA must match ${SCHEMA_RE} (got "${schema}")`);
  }
  return schema;
}

/** Postgres server URL without a database name. */
export function testServerUrl(): string {
  return (
    process.env.TEST_PG_URL?.trim() || 'postgresql://cipherdrop:cipherdrop@localhost:55433'
  ).replace(/\/+$/, '');
}

export function testDatabaseUrl(schema: string = testSchema()): string {
  return `${testServerUrl()}/${TEST_DB_NAME}?schema=${schema}`;
}

/** The maintenance database used to CREATE DATABASE cipherdrop_test. */
export function maintenanceDatabaseUrl(): string {
  return `${testServerUrl()}/postgres`;
}

export function testRedisUrl(): string {
  const db = process.env.TEST_REDIS_DB?.trim() || '15';
  if (!/^\d{1,2}$/.test(db))
    throw new Error(`TEST_REDIS_DB must be a Redis DB number (got "${db}")`);
  const base = (process.env.TEST_REDIS_BASE_URL?.trim() || 'redis://localhost:56380').replace(
    /\/+$/,
    '',
  );
  return `${base}/${db}`;
}
