/**
 * Rate limits (spec section 10 table, R10). express-rate-limit 7 + rate-limit-redis 4; each limiter has its
 * own RedisStore with prefix `${KEY_PREFIX}:rl:${name}:` (ioredis via sendCommand).
 *
 * Usage in a route factory:  ctx.rateLimit({ name: 'login', key: (req) => `${ipKey(req.ip)}|${email}` })
 * windowMs/limit default to RATE_LIMIT_RULES[name]; custom names must pass both.
 *
 * Enablement: env RATE_LIMITS_ENABLED (default true; refused false in production) overridden per app by
 * createApp({ rateLimits: boolean | { [name]: boolean } }). A disabled limiter is a pass-through.
 * Exceeding a limit answers 429 RATE_LIMITED with Retry-After.
 */
import type { Request, RequestHandler } from 'express';
import { rateLimit as expressRateLimit } from 'express-rate-limit';
import type { Redis } from 'ioredis';
import { RedisStore, type RedisReply } from 'rate-limit-redis';
import { rateLimited } from './errors';
import type { Logger } from './logger';

const MIN = 60_000;
const HOUR = 60 * MIN;

/** Spec section 10 limits. Keys are chosen by the caller (per IP, IP+email, drop+IP, token...). */
export const RATE_LIMIT_RULES = {
  /** 600/min per IP on /api, except chunk PUT/GET (mounted by createApp). */
  global: { windowMs: MIN, limit: 600 },
  /** prelogin and login: 10 per 15 min per IP+email. */
  prelogin: { windowMs: 15 * MIN, limit: 10 },
  login: { windowMs: 15 * MIN, limit: 10 },
  /** Not in the spec table: /auth/login/mfa code attempts, 10 per 15 min per IP. */
  loginMfa: { windowMs: 15 * MIN, limit: 10 },
  register: { windowMs: HOUR, limit: 5 },
  recovery: { windowMs: HOUR, limit: 5 },
  createDropAnon: { windowMs: HOUR, limit: 10 },
  createDropUser: { windowMs: HOUR, limit: 60 },
  /** Per upload token / download token (exempt from the global limiter). Key on sha256B64url(token). */
  chunkPut: { windowMs: MIN, limit: 1200 },
  chunkGet: { windowMs: MIN, limit: 1200 },
  /**
   * Per IP on chunk PUT/GET, in front of the per-token limiters (a random token gets a fresh bucket there).
   * Generous on purpose: ~180 chunks/min is one fast upload, and NAT'd users share an IP.
   */
  chunkIp: { windowMs: MIN, limit: 6000 },
  open: { windowMs: HOUR, limit: 30 },
  /**
   * Password guesses (wrong authKey) on /unlock and /open, one shared budget: 5 failures per 15 min per
   * drop+IP, and 20 failures per hour per drop. Correct keys are not counted.
   */
  unlockDropIp: { windowMs: 15 * MIN, limit: 5 },
  unlockDrop: { windowMs: HOUR, limit: 20 },
  report: { windowMs: HOUR, limit: 5 },
} as const satisfies Record<string, { windowMs: number; limit: number }>;

export type LimiterName = keyof typeof RATE_LIMIT_RULES;

/** createApp({ rateLimits }) override: everything on/off, or per limiter name. */
export type RateLimitsConfig = boolean | Partial<Record<LimiterName | (string & {}), boolean>>;

export interface RateLimitOptions {
  name: LimiterName | (string & {});
  /** Defaults to RATE_LIMIT_RULES[name].windowMs. */
  windowMs?: number;
  /** Defaults to RATE_LIMIT_RULES[name].limit. */
  limit?: number;
  /** Bucket key. Never put raw tokens or emails in clear text if avoidable: hash them (sha256B64url). */
  key: (req: Request) => string | Promise<string>;
  skip?: (req: Request) => boolean | Promise<boolean>;
  /**
   * Count only failed requests (status >= 400): a request that finishes below 400 is taken back out of its
   * bucket. A 429 is itself a failure, so a full bucket stays full.
   */
  skipSuccessfulRequests?: boolean;
}

export type RateLimitFactory = (options: RateLimitOptions) => RequestHandler;

export interface RateLimitDeps {
  redis: Redis;
  keyPrefix: string;
  /** Default from env RATE_LIMITS_ENABLED. */
  enabledByDefault: boolean;
  overrides?: RateLimitsConfig;
  /** Where a failed success-path refund is reported (see RefundSafeRedisStore). */
  logger?: Pick<Logger, 'warn'>;
}

export function isLimiterEnabled(
  name: string,
  deps: Pick<RateLimitDeps, 'enabledByDefault' | 'overrides'>,
) {
  const o = deps.overrides;
  if (typeof o === 'boolean') return o;
  if (o && typeof o[name] === 'boolean') return o[name] as boolean;
  return deps.enabledByDefault;
}

const passThrough: RequestHandler = (_req, _res, next) => next();

/**
 * A RedisStore whose decrement never rejects. express-rate-limit runs the skipSuccessfulRequests refund in a
 * 'finish' listener nobody awaits, so a Redis error there would be an unhandled rejection (fatalHandlers exit
 * the process). The refund is best-effort: a lost DECR only leaves one extra hit in the bucket. increment()
 * is unchanged, so a Redis error on the request path still fails that request.
 */
class RefundSafeRedisStore extends RedisStore {
  readonly #onError: (err: unknown) => void;

  constructor(
    options: ConstructorParameters<typeof RedisStore>[0],
    onError: (err: unknown) => void,
  ) {
    super(options);
    this.#onError = onError;
  }

  override async decrement(key: string): Promise<void> {
    try {
      await super.decrement(key);
    } catch (err) {
      this.#onError(err);
    }
  }
}

/** Build the per-app `ctx.rateLimit` factory. */
export function createRateLimitFactory(deps: RateLimitDeps): RateLimitFactory {
  return function rateLimit(options: RateLimitOptions): RequestHandler {
    if (!isLimiterEnabled(options.name, deps)) return passThrough;
    const rule = (
      RATE_LIMIT_RULES as Record<string, { windowMs: number; limit: number } | undefined>
    )[options.name];
    const windowMs = options.windowMs ?? rule?.windowMs;
    const limit = options.limit ?? rule?.limit;
    if (windowMs === undefined || limit === undefined) {
      throw new Error(`rateLimit("${options.name}"): unknown limiter, pass windowMs and limit`);
    }
    return expressRateLimit({
      windowMs,
      limit,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      keyGenerator: options.key,
      skip: options.skip,
      skipSuccessfulRequests: options.skipSuccessfulRequests ?? false,
      store: new RefundSafeRedisStore(
        {
          prefix: `${deps.keyPrefix}:rl:${options.name}:`,
          sendCommand: (command: string, ...args: string[]) =>
            deps.redis.call(command, ...args) as Promise<RedisReply>,
        },
        (err) =>
          deps.logger?.warn(
            { err: { code: (err as { code?: string } | null)?.code }, limiter: options.name },
            'rate limit refund failed',
          ),
      ),
      handler: (req, _res, next) => {
        const resetTime = (req as Request & { rateLimit?: { resetTime?: Date } }).rateLimit
          ?.resetTime;
        const retryAfterSec = resetTime
          ? Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000))
          : Math.ceil(windowMs / 1000);
        next(rateLimited(retryAfterSec));
      },
    });
  };
}
