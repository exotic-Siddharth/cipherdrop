import { describe, expect, it } from 'vitest';
import { ARGON2_RETRY_AFTER_SEC, createArgon2Limiter } from './argon2Limiter';
import { isAppError } from './errors';
import { metricsRegistry } from './metrics';

/** A task that runs until release() is called. */
function blocker() {
  let release!: () => void;
  let started = false;
  const task = () =>
    new Promise<string>((resolve) => {
      started = true;
      release = () => resolve('done');
    });
  return {
    task,
    release: () => release(),
    get started() {
      return started;
    },
  };
}

const tick = () => new Promise((r) => setImmediate(r));

async function metric(name: string): Promise<number> {
  const found = (await metricsRegistry.getMetricsAsJSON()).find((m) => m.name === name);
  return Number(found?.values[0]?.value ?? 0);
}

describe('Argon2 limiter (critic-1)', () => {
  it('runs at most maxConcurrent tasks and starts waiting ones in FIFO order', async () => {
    const limiter = createArgon2Limiter({ maxConcurrent: 2, maxQueue: 5 });
    const tasks = Array.from({ length: 4 }, blocker);
    const order: number[] = [];
    const runs = tasks.map((b, i) =>
      limiter.run(async () => {
        order.push(i);
        return b.task();
      }),
    );
    await tick();
    expect(tasks.map((b) => b.started)).toEqual([true, true, false, false]);
    expect([limiter.active, limiter.queued]).toEqual([2, 2]);

    tasks[1]!.release();
    await tick();
    expect(tasks.map((b) => b.started)).toEqual([true, true, true, false]);
    expect([limiter.active, limiter.queued]).toEqual([2, 1]);
    tasks[0]!.release();
    tasks[2]!.release();
    await tick();
    tasks[3]!.release();
    expect(await Promise.all(runs)).toEqual(['done', 'done', 'done', 'done']);
    expect(order).toEqual([0, 1, 2, 3]);
    expect([limiter.active, limiter.queued]).toEqual([0, 0]);
  });

  it('refuses with 429 RATE_LIMITED and Retry-After once the queue is full, without running the task', async () => {
    const limiter = createArgon2Limiter({ maxConcurrent: 1, maxQueue: 1 });
    const running = blocker();
    const waiting = blocker();
    const first = limiter.run(running.task);
    const second = limiter.run(waiting.task);
    const rejectedBefore = await metric('argon2_rejected_total');
    let ran = false;
    const err = await limiter
      .run(async () => {
        ran = true;
      })
      .catch((e: unknown) => e);
    expect(ran).toBe(false);
    expect(isAppError(err) && [err.status, err.code, err.retryAfterSec]).toEqual([
      429,
      'RATE_LIMITED',
      ARGON2_RETRY_AFTER_SEC,
    ]);
    expect(await metric('argon2_rejected_total')).toBe(rejectedBefore + 1);
    expect(await metric('argon2_active')).toBeGreaterThanOrEqual(1);
    expect(await metric('argon2_queued')).toBeGreaterThanOrEqual(1);
    running.release();
    await tick();
    waiting.release();
    await Promise.all([first, second]);
    expect([limiter.active, limiter.queued]).toEqual([0, 0]);
  });

  it('frees the slot when a task fails, and passes the error through', async () => {
    const limiter = createArgon2Limiter({ maxConcurrent: 1, maxQueue: 0 });
    await expect(limiter.run(() => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
    expect(limiter.active).toBe(0);
    expect(await limiter.run(() => Promise.resolve(42))).toBe(42);
  });
});
