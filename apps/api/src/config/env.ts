/**
 * zod-validated environment (spec section 6, R10, R26). Parsed once at import: the process fails fast with a
 * list of invalid variable NAMES (values are never printed: some are secrets).
 *
 * apps/api/.env is loaded with process.loadEnvFile() when present (variables already set in the environment
 * win). It is NOT loaded under NODE_ENV=test (tests are hermetic: test/setup.ts sets every value) nor under
 * NODE_ENV=production (the real environment is the only source there; DATABASE_URL, REDIS_URL, WEB_ORIGIN and
 * TRUST_PROXY must be stated, COOKIE_SECURE must be true, WEB_ORIGIN a bare origin).
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
    /** A chunk GET whose client reads nothing for this long is aborted (frees its storage socket). */
    CHUNK_IDLE_TIMEOUT_SEC: int(30, 1, 3_600),
    /**
     * Chunk GETs streaming in this process (each holds a storage stream, an S3 socket). The maximum keeps it
     * below the S3 driver's 256-socket pool, so uploads, deletes and /readyz always find a socket.
     */
    MAX_CONCURRENT_CHUNK_DOWNLOADS: int(192, 1, 224),
    /** Chunk GETs in flight per download grant / per client IP (the web downloader fetches one at a time). */
    MAX_CHUNK_DOWNLOADS_PER_GRANT: int(8, 1, 10_000),
    MAX_CHUNK_DOWNLOADS_PER_IP: int(32, 1, 10_000),
    /** Chunk PUTs in flight per API process (each buffers up to 4 MiB); more get 429 + Retry-After. */
    MAX_CONCURRENT_CHUNK_UPLOADS: int(64, 1, 10_000),
    /** Chunk PUTs in flight per upload token / per client IP (the web uploader sends 3 at a time). */
    MAX_CHUNK_UPLOADS_PER_TOKEN: int(8, 1, 10_000),
    MAX_CHUNK_UPLOADS_PER_IP: int(16, 1, 10_000),
    /** A chunk PUT whose body sends nothing for this long is hung up (stalled clients). */
    CHUNK_UPLOAD_IDLE_TIMEOUT_SEC: int(30, 1, 3_600),
    /**
     * A chunk PUT whose body is still incomplete this long after it took its slot is hung up (slow-drip
     * clients that send a byte now and then; a full 4 MiB chunk in 120 s needs about 35 KB/s).
     */
    CHUNK_UPLOAD_DEADLINE_SEC: int(120, 1, 3_600),
    /** Ceiling on the ciphertext bytes of anonymous drops whose blobs are not purged yet (0 = no ceiling). */
    ANON_TOTAL_PENDING_BYTES: int(0, 0),

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
    if (!env.COOKIE_SECURE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['COOKIE_SECURE'],
        message: 'must be true in production (the refresh cookie must be Secure)',
      });
    }
    // CORS compares the Origin header to this string exactly: no path, no trailing slash.
    if (!URL.canParse(env.WEB_ORIGIN) || new URL(env.WEB_ORIGIN).origin !== env.WEB_ORIGIN) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['WEB_ORIGIN'],
        message: 'must be a bare origin such as https://drop.example (no path, no trailing slash)',
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

/** Variables that have a local-dev default in the schema and so must be stated in production. */
const EXPLICIT_IN_PRODUCTION = [
  ['DATABASE_URL', 'must be set explicitly in production (no dev default)'],
  ['REDIS_URL', 'must be set explicitly in production (no dev default)'],
  ['WEB_ORIGIN', 'must be set explicitly in production (no dev default)'],
  ['TRUST_PROXY', 'must be set in production (hop count; 0 = no reverse proxy)'],
] as const;

/** Parse an environment record (tests can call this with a custom record). */
export function parseEnv(source: Record<string, string | undefined>): Env {
  const result = EnvSchema.safeParse(source);
  const lines = result.success
    ? []
    : result.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
  if (source.NODE_ENV === 'production') {
    for (const [key, message] of EXPLICIT_IN_PRODUCTION) {
      if ((source[key] ?? '').trim() === '') lines.push(`  - ${key}: ${message}`);
    }
  }
  if (!result.success || lines.length > 0) {
    throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
  }
  return result.data;
}

function loadDotEnv(): void {
  // Production configuration comes from the real environment only: a stray dev apps/api/.env must not fill it.
  if (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'production') return;
  const file = path.join(apiRoot, '.env');
  if (existsSync(file)) process.loadEnvFile(file);
}

loadDotEnv();

export const env: Env = parseEnv(process.env);
