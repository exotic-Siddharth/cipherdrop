/**
 * Prisma's warn and error events (db/prisma.ts): a failed call's message renders its arguments, so it is left
 * out; the engine's own messages (a connection that broke in the background) are kept, or nobody would know.
 * The real-client tests pin the two target formats logPrismaEvent tells apart.
 */
import { randomBytes } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { env } from '../config/env';
import { createLogger } from '../lib/logger';
import { createPrisma, logPrismaEvent } from './prisma';

const SECRET = 'NHQLjAoPm44F9kDrwhV7u3CPHHucOoBzVFOBmVwdGmw';

function captured() {
  const lines: string[] = [];
  const log = createLogger({ level: 'trace', destination: { write: (s) => lines.push(s) } });
  const records = () => lines.map((l) => JSON.parse(l) as Record<string, unknown>);
  return { lines, log, records };
}

const clients: PrismaClient[] = [];
afterAll(async () => {
  await Promise.all(clients.map((c) => c.$disconnect()));
});

describe('logPrismaEvent', () => {
  it("leaves out a failed call's message and keeps the engine's", () => {
    const { lines, log, records } = captured();
    logPrismaEvent(log, 'error', {
      target: 'report.create',
      message: `Invalid \`prisma.report.create()\` invocation: { providedKey: "${SECRET}" }`,
    });
    logPrismaEvent(log, 'error', {
      target: '$queryRaw',
      message: `Raw query failed. Message: \`invalid input syntax for type uuid: "${SECRET}"\``,
    });
    logPrismaEvent(log, 'warn', { target: '', message: `Attempt 1/3 failed: ${SECRET}` });
    logPrismaEvent(log, 'error', {
      target: 'quaint::connector::postgres::native',
      message: 'Error in PostgreSQL connection: Error { kind: Closed, cause: None }',
    });
    expect(lines.join('')).not.toContain(SECRET);
    expect(records()).toMatchObject([
      { level: 50, msg: 'prisma error', prisma: { target: 'report.create' } },
      { level: 50, msg: 'prisma error', prisma: { target: '$queryRaw' } },
      { level: 40, msg: 'prisma warn', prisma: { target: '' } },
      {
        level: 50,
        msg: 'Error in PostgreSQL connection: Error { kind: Closed, cause: None }',
        prisma: { target: 'quaint::connector::postgres::native' },
      },
    ]);
  });
});

describe('createPrisma', () => {
  it('reports a rejected call under its name, without the arguments', async () => {
    const { lines, log, records } = captured();
    const prisma = createPrisma(env.DATABASE_URL, log);
    clients.push(prisma);
    await expect(
      prisma.report.create({
        data: { dropId: 'x', reason: 'NOT_A_REASON' as never, providedKey: SECRET },
      }),
    ).rejects.toThrow(SECRET);
    expect(lines.join('')).not.toContain(SECRET);
    expect(records()).toContainEqual(
      expect.objectContaining({ msg: 'prisma error', prisma: { target: 'report.create' } }),
    );
  });

  it('logs why a connection broke in the background (an engine target, message kept)', async () => {
    const { log, records } = captured();
    // Its own application_name, so only this client's connections are terminated.
    const appName = `cd_prisma_test_${randomBytes(4).toString('hex')}`;
    const prisma = createPrisma(`${env.DATABASE_URL}&application_name=${appName}`, log);
    const killer = new PrismaClient({ datasourceUrl: env.DATABASE_URL });
    clients.push(prisma, killer);
    await prisma.$queryRaw`SELECT 1`;
    await killer.$queryRaw`
      SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = ${appName}`;
    await vi.waitFor(
      () =>
        expect(records()).toContainEqual(
          expect.objectContaining({
            level: 50,
            msg: expect.stringMatching(/^Error in PostgreSQL connection/),
            prisma: { target: expect.stringContaining('::') },
          }),
        ),
      { timeout: 10_000, interval: 100 },
    );
  });
});
