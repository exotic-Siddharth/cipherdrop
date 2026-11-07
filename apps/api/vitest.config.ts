import { defineConfig } from 'vitest/config';

/**
 * API tests run against real Postgres + Redis from docker-compose (database `cipherdrop_test`, created by the
 * global setup; schema `TEST_SCHEMA`, default `test`; Redis DB `TEST_REDIS_DB`, default 15). See test/config.ts.
 * Lanes: TEST_SCHEMA=lane_<id> TEST_REDIS_DB=<n> npx vitest run src/modules/<area>
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    globalSetup: ['./test/globalSetup.ts'],
    setupFiles: ['./test/setup.ts'],
    // R2: one file at a time; each file still gets its own KEY_PREFIX and temp STORAGE_DIR.
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
