/**
 * Per-test-file setup (vitest setupFiles). Runs before the test file imports anything from src/, so
 * config/env.ts parses THESE values. Do not import from src/ here.
 *
 * Every test file gets a unique KEY_PREFIX and its own temp STORAGE_DIR. Rate limits are OFF by default:
 * tests that exercise them pass `createApp({ rateLimits: true })` (or a per-limiter record).
 * TRUST_PROXY=1 lets tests simulate client IPs with an X-Forwarded-For header.
 */
import { randomUUID } from 'node:crypto';
import { afterAll } from 'vitest';
import { testDatabaseUrl, testRedisUrl, testSchema } from './config';
import { removeDir, tempStorageDir } from './storage';

const storageDir = tempStorageDir();

Object.assign(process.env, {
  NODE_ENV: 'test',
  DATABASE_URL: testDatabaseUrl(),
  REDIS_URL: testRedisUrl(),
  KEY_PREFIX: `cdt:${testSchema()}:${randomUUID().slice(0, 8)}`,
  JWT_ACCESS_SECRET: 'test-only-jwt-access-secret-0123456789abcdef',
  PRELOGIN_SECRET: 'test-only-prelogin-hmac-secret-0123456789abcdef',
  TOTP_ENC_KEY: Buffer.alloc(32, 7).toString('base64'),
  COOKIE_SECURE: 'false',
  STORAGE_DRIVER: 'local',
  STORAGE_DIR: storageDir,
  RATE_LIMITS_ENABLED: 'false',
  TRUST_PROXY: '1',
  LOG_LEVEL: process.env.TEST_LOG_LEVEL ?? 'silent',
  LOG_PRETTY: 'false',
  WEB_ORIGIN: 'http://localhost:5174',
});

afterAll(async () => {
  await removeDir(storageDir);
});
