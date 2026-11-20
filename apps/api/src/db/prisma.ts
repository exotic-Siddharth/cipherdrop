import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';
import { logger as defaultLogger, type Logger } from '../lib/logger';

/**
 * A new client. Prisma never logs query parameters here (no `query` level). Its warnings and errors are
 * emitted as events and written through pino (logPrismaEvent): Prisma's own stdout logging would bypass pino,
 * its redaction and its error serializer. errorFormat 'minimal' leaves the source code frame out of the
 * messages.
 */
export function createPrisma(
  url: string = env.DATABASE_URL,
  log: Logger = defaultLogger,
): PrismaClient {
  const prisma = new PrismaClient({
    datasourceUrl: url,
    errorFormat: 'minimal',
    log: [
      { emit: 'event', level: 'warn' },
      { emit: 'event', level: 'error' },
    ],
  });
  prisma.$on('warn', (e) => logPrismaEvent(log, 'warn', e));
  prisma.$on('error', (e) => logPrismaEvent(log, 'error', e));
  return prisma;
}

/**
 * One Prisma warn or error event. Its `target` says where it comes from. A failed call is reported under the
 * call's name ("report.create", "$queryRaw"), with the message of the error the caller gets, which renders
 * the call's arguments (a reporter's decryption key, a manifest) or the database's error with the values,
 * whatever errorFormat says: that message is left out. The thrown error reaches the caller and the error
 * handler, which log its safe fields (lib/logger.ts serializeError). The engine's own logs come from a Rust
 * module ("quaint::connector::postgres::native"): a connection that broke in the background, which no caller
 * ever hears about. They are written by the engine, not rendered from a call, so their message is kept.
 */
export function logPrismaEvent(
  log: Pick<Logger, 'warn' | 'error'>,
  level: 'warn' | 'error',
  e: { message: string; target: string },
): void {
  const target = typeof e.target === 'string' ? e.target : '';
  log[level]({ prisma: { target } }, target.includes('::') ? e.message : `prisma ${level}`);
}

let shared: PrismaClient | undefined;
/** Process-wide client (index.ts and createApp() defaults). */
export function getPrisma(): PrismaClient {
  shared ??= createPrisma();
  return shared;
}
