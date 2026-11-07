/**
 * zod-validated environment (spec section 6, R10, R26). Parsed once at import: the process fails fast with a
 * list of invalid variable NAMES (values are never printed: some are secrets).
 *
 * apps/api/.env is loaded with process.loadEnvFile() when present (variables already set in the environment
 * win). It is NOT loaded under NODE_ENV=test: tests are hermetic (test/setup.ts sets every value).
 * Secrets have no defaults here; local dev values live in apps/api/.env (template: .env.example).
 */
import { existsSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { apiRoot } from './paths';

const TRUE = new Set(['true', '1', 'yes', 'on']);
const FALSE = new Set(['false', '0', 'no', 'off']);

const bool = (fallback: boolean) =>
  z.preprocess((v) => {
    if (v === undefined || v === '') return fallback;
    const s = String(v).trim().toLowerCase();
    if (TRUE.has(s)) return true;
    if (FALSE.has(s)) return false;
    return v;
  }, z.boolean());

const int = (fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER) =>
  z.preprocess(
    (v) => (v === undefined || v === '' ? fallback : Number(v)),
    z.number().int().min(min).max(max),
  );

/** TRUST_PROXY is a hop count (R10): "false"/"0"/unset -> 0, "true" -> 1, "2" -> 2. */
const hopCount = z.preprocess((v) => {
  if (v === undefined || v === '') return 0;
  const s = String(v).trim().toLowerCase();
  if (FALSE.has(s)) return 0;
  if (s === 'true') return 1;
  return Number(s);
}, z.number().int().min(0).max(10));

const base64Key32 = z
  .string()
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'must be base64')
  .refine((v) => Buffer.from(v, 'base64').length === 32, 'must decode to exactly 32 bytes');

const secret = z.string().min(32, 'must be at least 32 characters');

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    API_PORT: int(4100, 0, 65535),
    WEB_ORIGIN: z.string().url().default('http://localhost:5174'),

    DATABASE_URL: z
      .string()
      .url()
      .default('postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop?schema=public'),
    REDIS_URL: z.string().url().default('redis://localhost:56380/0'),
    /** Prefix of EVERY Redis key: `${KEY_PREFIX}:revoked:sid:<sid>`, `${KEY_PREFIX}:rl:<name>:`, `${KEY_PREFIX}:lock:<name>` (R2). */
    KEY_PREFIX: z
      .string()
      .regex(/^[A-Za-z0-9:_-]{1,64}$/)
      .default('cd'),

    JWT_ACCESS_SECRET: secret,
    ACCESS_TOKEN_TTL_SEC: int(900, 60, 86_400),
    REFRESH_TOKEN_TTL_DAYS: int(30, 1, 365),
    COOKIE_SECURE: bool(false),
    /** 32 bytes, base64: AES-256-GCM key for TOTP secrets at rest. */
    TOTP_ENC_KEY: base64Key32,
    /** HMAC key for deterministic fake prelogin salts. */
    PRELOGIN_SECRET: secret,

    STORAGE_DRIVER: z.enum(['local', 's3']).default('local'),
    /** Absolute after parsing; relative values resolve against apps/api (gitignored apps/api/data/). */
    STORAGE_DIR: z
      .string()
      .min(1)
      .default('./data/blobs')
      .transform((p) => (path.isAbsolute(p) ? p : path.resolve(apiRoot, p))),
    S3_ENDPOINT: z.string().url().optional(),
    S3_REGION: z.string().min(1).default('us-east-1'),
    S3_BUCKET: z.string().min(3).default('cipherdrop'),
    S3_ACCESS_KEY_ID: z.string().min(1).optional(),
    S3_SECRET_ACCESS_KEY: z.string().min(1).optional(),
    S3_FORCE_PATH_STYLE: bool(true),

    ANON_MAX_DROP_BYTES: int(104_857_600, 1),
    USER_MAX_DROP_BYTES: int(2_147_483_648, 1),
    USER_DEFAULT_QUOTA_BYTES: int(5_368_709_120, 0),
    ANON_MAX_EXPIRY_HOURS: int(72, 1, 720),
    USER_MAX_EXPIRY_HOURS: int(720, 1, 720),
    MAX_FILES_PER_DROP: int(20, 1, 20),
    DOWNLOAD_GRANT_TTL_MIN: int(30, 1, 24 * 60),
    CLEANUP_INTERVAL_SEC: int(60, 1, 86_400),

    TRUST_PROXY: hopCount,
    RATE_LIMITS_ENABLED: bool(true),
    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    LOG_PRETTY: bool(false),

    SEED_ADMIN_PASSWORD: z.string().min(1).optional(),
    SEED_DEMO_PASSWORD: z.string().min(1).optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV !== 'production') return;
    if (!env.RATE_LIMITS_ENABLED) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['RATE_LIMITS_ENABLED'],
        message: 'rate limits cannot be disabled in production',
      });
    }
    for (const key of ['JWT_ACCESS_SECRET', 'PRELOGIN_SECRET', 'TOTP_ENC_KEY'] as const) {
      const value = env[key];
      const decoded =
        key === 'TOTP_ENC_KEY' ? Buffer.from(value, 'base64').toString('latin1') : value;
      if (/dev-only|test-only|change-me/i.test(decoded)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: 'a development/test secret cannot be used in production',
        });
      }
    }
  });

export type Env = z.infer<typeof EnvSchema>;

/** Parse an environment record (tests can call this with a custom record). */
export function parseEnv(source: Record<string, string | undefined>): Env {
  const result = EnvSchema.safeParse(source);
  if (!result.success) {
    const lines = result.error.issues.map(
      (i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`,
    );
    throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
  }
  return result.data;
}

function loadDotEnv(): void {
  if (process.env.NODE_ENV === 'test') return;
  const file = path.join(apiRoot, '.env');
  if (existsSync(file)) process.loadEnvFile(file);
}

loadDotEnv();

export const env: Env = parseEnv(process.env);
