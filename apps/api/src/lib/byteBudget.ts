/**
 * Rolling per-client byte budget for anonymous drops (server-1): at most `limitBytes` of declared ciphertext
 * per client in any `windowHours`. The client is ipShareKey(req.ip): the IPv4 address or the IPv6 /48.
 *
 * Coarse on purpose. One Redis hash per client, `${KEY_PREFIX}:anonbytes:<client>`: field = the hour of the
 * create (floor(ms / 1 h)), value = the MiB that client's creates took in that hour, each create rounded UP to
 * a whole MiB. reserve() runs one Lua script, so parallel creates cannot overshoot: it deletes the hours that
 * left the window, sums the rest and adds the new create only if it fits; otherwise it answers how long until
 * enough old hours leave (the Retry-After). An hour counts for `windowHours` full hours after the one it
 * names, so a create counts for at least the window and at most one hour more. Rounding up keeps the budget
 * conservative (a 2 KiB drop takes 1 MiB). The key expires when its newest hour leaves the window, so an idle
 * client leaves nothing behind.
 *
 * Metadata: Redis holds, for the window, the client key with the MiB total of its anonymous creates per hour.
 * Not the drop id, not the exact create time, not the exact size: a Drop row's createdAt and
 * totalCiphertextBytes match a bucket only as "a create of about that size in that hour". That does not make
 * it unlinkable. Whoever reads both Redis and the database (the operator, or anyone who owns the host) can
 * still tie a client key to an anonymous drop when few anonymous drops were created in that hour, which on a
 * quiet instance is the usual case. The database itself stores no creator address.
 */
import type { Redis } from 'ioredis';
import { redisKey } from './redis';

const HOUR_MS = 3_600_000;
/** The budget's unit: every create is rounded up to a whole MiB. */
export const BUDGET_UNIT_BYTES = 1024 * 1024;

/** Whole budget units (MiB) a create of `bytes` takes. */
export const budgetUnits = (bytes: number) => Math.ceil(bytes / BUDGET_UNIT_BYTES);

/**
 * KEYS[1] the client's hash. ARGV: hour (the create's hour bucket), nowMs, windowHours, limitUnits, units.
 * Returns 0 when the create fits (and was added), otherwise the milliseconds until it would fit.
 */
const RESERVE_LUA = `
local key = KEYS[1]
local hour = tonumber(ARGV[1])
local nowMs = tonumber(ARGV[2])
local windowHours = tonumber(ARGV[3])
local limit = tonumber(ARGV[4])
local units = tonumber(ARGV[5])
local hourMs = ${HOUR_MS}
local oldest = hour - windowHours
local fields = redis.call('HGETALL', key)
local buckets = {}
local used = 0
for i = 1, #fields, 2 do
  local b = tonumber(fields[i])
  local u = tonumber(fields[i + 1])
  if b < oldest then
    redis.call('HDEL', key, fields[i])
  else
    used = used + u
    buckets[#buckets + 1] = { b, u }
  end
end
if used + units <= limit then
  redis.call('HINCRBY', key, ARGV[1], units)
  redis.call('PEXPIRE', key, (hour + windowHours + 1) * hourMs - nowMs)
  return 0
end
if units > limit then return (windowHours + 1) * hourMs end
table.sort(buckets, function(a, b) return a[1] < b[1] end)
local excess = used + units - limit
for _, bucket in ipairs(buckets) do
  excess = excess - bucket[2]
  if excess <= 0 then return math.max(1, (bucket[1] + windowHours + 1) * hourMs - nowMs) end
end
return (windowHours + 1) * hourMs
`;

/** KEYS[1] the client's hash. ARGV: hour, units. Takes `units` back out of that hour. */
const RELEASE_LUA = `
local left = redis.call('HINCRBY', KEYS[1], ARGV[1], -tonumber(ARGV[2]))
if left <= 0 then redis.call('HDEL', KEYS[1], ARGV[1]) end
return left
`;

export const anonBytesKey = (client: string) => redisKey('anonbytes', client);

export interface ByteBudget {
  limitBytes: number;
  windowHours: number;
}

export type ReserveResult =
  { ok: true; release: () => Promise<void> } | { ok: false; retryAfterMs: number };

/**
 * Reserve `bytes` (rounded up to whole MiB) in the budget of `client` at time `now`. On success, `release()`
 * gives them back (for a create that fails after the reservation); it never rejects.
 */
export async function reserveBytes(
  redis: Redis,
  budget: ByteBudget,
  client: string,
  bytes: number,
  now: Date,
): Promise<ReserveResult> {
  const key = anonBytesKey(client);
  const hour = String(Math.floor(now.getTime() / HOUR_MS));
  const units = budgetUnits(bytes);
  const waitMs = Number(
    await redis.eval(
      RESERVE_LUA,
      1,
      key,
      hour,
      String(now.getTime()),
      String(budget.windowHours),
      String(Math.floor(budget.limitBytes / BUDGET_UNIT_BYTES)),
      String(units),
    ),
  );
  if (waitMs > 0) return { ok: false, retryAfterMs: waitMs };
  return {
    ok: true,
    release: async () => {
      await redis.eval(RELEASE_LUA, 1, key, hour, String(units)).catch(() => undefined);
    },
  };
}
