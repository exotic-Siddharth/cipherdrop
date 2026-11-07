/**
 * Redis client and key helpers (R2). EVERY key is prefixed with env KEY_PREFIX (default `cd`):
 *   `${KEY_PREFIX}:revoked:sid:<sid>`   access-token denylist (TTL = ACCESS_TOKEN_TTL_SEC)
 *   `${KEY_PREFIX}:rl:<limiter>:<key>`  rate limits (lib/rateLimit.ts)
 *   `${KEY_PREFIX}:lock:<name>`         locks, e.g. lock:cleanup
 * No ioredis `keyPrefix` option is used: keys are built explicitly with redisKey().
 */
import { Redis } from 'ioredis';
import { env } from '../config/env';
import { logger } from './logger';
import { randomToken } from './tokens';

export type { Redis } from 'ioredis';

export function createRedis(url: string = env.REDIS_URL): Redis {
  const client = new Redis(url, { maxRetriesPerRequest: 3 });
  let lastLog = 0;
  client.on('error', (err: Error) => {
    const now = Date.now();
    if (now - lastLog > 10_000) {
      lastLog = now;
      logger.warn({ err: { message: err.message } }, 'redis connection error');
    }
  });
  return client;
}

let shared: Redis | undefined;
/** Process-wide client (index.ts and createApp() defaults). */
export function getRedis(): Redis {
  shared ??= createRedis();
  return shared;
}

/** Build a prefixed key: redisKey('lock', 'cleanup') -> "cd:lock:cleanup". */
export function redisKey(...parts: (string | number)[]): string {
  return [env.KEY_PREFIX, ...parts].join(':');
}

export const sidDenylistKey = (sid: string) => redisKey('revoked', 'sid', sid);

/** Reject every access token of this session immediately (spec section 10). */
export async function denylistSid(
  redis: Redis,
  sid: string,
  ttlSec: number = env.ACCESS_TOKEN_TTL_SEC,
): Promise<void> {
  await redis.set(sidDenylistKey(sid), '1', 'EX', ttlSec);
}

export async function isSidDenylisted(redis: Redis, sid: string): Promise<boolean> {
  return (await redis.exists(sidDenylistKey(sid))) === 1;
}

/** SET NX PX lock. Returns the owner token, or null when another holder has it. */
export async function acquireLock(
  redis: Redis,
  name: string,
  ttlMs: number,
): Promise<string | null> {
  const token = randomToken(16);
  const ok = await redis.set(redisKey('lock', name), token, 'PX', ttlMs, 'NX');
  return ok === 'OK' ? token : null;
}

const RELEASE_LUA =
  "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";

/** Release a lock only if we still own it. */
export async function releaseLock(redis: Redis, name: string, token: string): Promise<boolean> {
  const released = (await redis.eval(RELEASE_LUA, 1, redisKey('lock', name), token)) as number;
  return released === 1;
}
