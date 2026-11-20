/**
 * Bounded server-side Argon2id work (review critic-1). Each account authKey hash or verification on a request
 * path (login and its dummy verification for unknown emails, register, password change, recovery, every
 * re-authentication) runs through the app's limiter, ctx.argon2: at most ARGON2_MAX_CONCURRENT at a time, at most
 * ARGON2_MAX_QUEUE more waiting in FIFO order. Past that the request fails at once with 429 RATE_LIMITED and
 * Retry-After, so a flood of logins costs a bounded amount of CPU and memory instead of an unbounded queue.
 *
 * Why it matters beyond CPU: @node-rs/argon2 runs on the libuv threadpool, which Node shares with fs (the local
 * storage driver's chunk reads and writes), dns.lookup (S3 and database host names) and async crypto. Unbounded,
 * a few dozen concurrent logins occupy every pool thread and chunk transfers stall behind them until their idle
 * timeouts cut them. With the cap below the pool size (env.ts enforces ARGON2_MAX_CONCURRENT < UV_THREADPOOL_SIZE),
 * at least UV_THREADPOOL_SIZE - ARGON2_MAX_CONCURRENT threads always stay free for that I/O.
 *
 * Sizing (defaults in config/env.ts). One hash at the server parameters (m=19 MiB, t=2, p=1) took 11 ms on the
 * 4-core Linux container used for verification (native @node-rs/argon2, 2026-11-20); allow up to about 30 ms on a
 * slower vCPU:
 * - ARGON2_MAX_CONCURRENT=2: Argon2id is CPU-bound on one core per hash (p=1), so more hashes in parallel than
 *   spare cores only add latency. Two leave the rest of a small host to Postgres, Redis and nginx, hold
 *   2 x 19 MiB = 38 MiB of Argon2 memory at most, and still give 2 / 11-30 ms = about 65-180 hashes per second per
 *   process, far above honest login traffic (the per-client limiters allow a few per minute).
 * - ARGON2_MAX_QUEUE=32: a full queue drains in 32 x 11-30 ms / 2 = about 0.2-0.5 s, so a queued login waits at
 *   most about half a second; a waiting request holds only a closure, no Argon2 memory.
 * - Retry-After 1 s: longer than it takes a full queue to drain.
 * One limiter per app, so per process in production (one app per process), like the in-flight chunk caps
 * (docs/DEPLOYMENT.md section 4): N instances run N times the work.
 */
import { rateLimited } from './errors';
import { metrics } from './metrics';

export interface Argon2Limits {
  /** Hashes running at the same time. */
  maxConcurrent: number;
  /** Hashes waiting for a slot; one more is refused with 429. */
  maxQueue: number;
}

export interface Argon2Limiter {
  /** Run one Argon2 task in a slot (waiting in line if needed); throws 429 RATE_LIMITED when the queue is full. */
  run<T>(task: () => Promise<T>): Promise<T>;
  readonly active: number;
  readonly queued: number;
}

/** Retry-After of a refused hash: a full queue drains in well under a second (see the sizing above). */
export const ARGON2_RETRY_AFTER_SEC = 1;

export function createArgon2Limiter(limits: Argon2Limits): Argon2Limiter {
  let active = 0;
  const waiting: (() => void)[] = [];

  /** A finished task hands its slot straight to the next one in line, so `active` never drops in between. */
  const release = () => {
    const next = waiting.shift();
    if (next) {
      metrics.argon2Queued.dec();
      next();
      return;
    }
    active -= 1;
    metrics.argon2Active.dec();
  };

  return {
    async run<T>(task: () => Promise<T>): Promise<T> {
      if (active < limits.maxConcurrent) {
        active += 1;
        metrics.argon2Active.inc();
      } else if (waiting.length < limits.maxQueue) {
        metrics.argon2Queued.inc();
        await new Promise<void>((resolve) => waiting.push(resolve));
      } else {
        metrics.argon2Rejected.inc();
        throw rateLimited(ARGON2_RETRY_AFTER_SEC);
      }
      try {
        return await task();
      } finally {
        release();
      }
    },
    get active() {
      return active;
    },
    get queued() {
      return waiting.length;
    },
  };
}
