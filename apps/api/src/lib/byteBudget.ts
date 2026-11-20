/**
 * Rolling per-client byte budget for anonymous drops (server-1): at most `limitBytes` of declared ciphertext
 * per client in any `windowMs`. The client is ipShareKey(req.ip): the IPv4 address or the IPv6 /48.
 *
 * One Redis sorted set per client, `${KEY_PREFIX}:anonbytes:<client>`, one member per accepted create:
 * member "<random id>:<bytes>", score = the create time in ms. reserve() runs one Lua script, so parallel
 * creates cannot overshoot: it drops the members older than the window, sums the rest and adds the new member
 * only if it fits. Otherwise it answers how long until enough old bytes leave the window (the Retry-After).
 * The key expires one window after its last member, so an idle client leaves nothing behind.
 *
 * Metadata: Redis holds the client key (as the rate limiters do, but for the budget window) with the time and
 * size of each anonymous create. The member id is random, never the drop id, so Redis does not link a client
 * address to a drop; the database still stores no creator address at all.
 */
import { randomBytes } from 'node:crypto';
import type { Redis } from 'ioredis';
import { redisKey } from './redis';

const RESERVE_LUA = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local bytes = tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local entries = redis.call('ZRANGE', key, 0, -1, 'WITHSCORES')
local used = 0
for i = 1, #entries, 2 do
  used = used + tonumber(string.match(entries[i], ':(%d+)$'))
end
if used + bytes <= limit then
  redis.call('ZADD', key, now, ARGV[5])
  redis.call('PEXPIRE', key, window)
  return 0
end
if bytes > limit then return window end
local excess = used + bytes - limit
for i = 1, #entries, 2 do
  excess = excess - tonumber(string.match(entries[i], ':(%d+)$'))
  if excess <= 0 then return math.max(1, tonumber(entries[i + 1]) + window - now) end
end
return window
`;

export const anonBytesKey = (client: string) => redisKey('anonbytes', client);

export interface ByteBudget {
  limitBytes: number;
  windowMs: number;
}

export type ReserveResult =
  { ok: true; release: () => Promise<void> } | { ok: false; retryAfterMs: number };

/**
 * Reserve `bytes` in the budget of `client` at time `now`. On success, `release()` gives the bytes back (for a
 * create that fails after the reservation); it never rejects.
 */
export async function reserveBytes(
  redis: Redis,
  budget: ByteBudget,
  client: string,
  bytes: number,
  now: Date,
): Promise<ReserveResult> {
  const key = anonBytesKey(client);
  const member = `${randomBytes(12).toString('base64url')}:${bytes}`;
  const waitMs = Number(
    await redis.eval(
      RESERVE_LUA,
      1,
      key,
      String(now.getTime()),
      String(budget.windowMs),
      String(budget.limitBytes),
      String(bytes),
      member,
    ),
  );
  if (waitMs > 0) return { ok: false, retryAfterMs: waitMs };
  return {
    ok: true,
    release: async () => {
      await redis.zrem(key, member).catch(() => undefined);
    },
  };
}
