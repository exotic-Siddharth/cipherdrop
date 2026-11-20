import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';
import { logger as defaultLogger, type Logger } from '../lib/logger';

/**
 * A new client. Prisma never logs query parameters here (no `query` level). Its warnings and errors are
 * emitted as events and written through pino: Prisma's own stdout logging would bypass pino, its redaction
 * and its error serializer. An error event is logged WITHOUT its message, which carries the arguments of the
 * failed call (a reporter's decryption key, a manifest) whatever errorFormat says; the thrown error reaches
 * the caller and the error handler, which logs its safe fields (lib/logger.ts serializeError).
 * errorFormat 'minimal' leaves the source code frame out of the messages.
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
  // `target` names the call (e.g. "report.create"), never its arguments.
  prisma.$on('warn', (e) => log.warn({ prisma: { target: e.target } }, e.message));
  prisma.$on('error', (e) => log.error({ prisma: { target: e.target } }, 'prisma error'));
  return prisma;
}

let shared: PrismaClient | undefined;
/** Process-wide client (index.ts and createApp() defaults). */
export function getPrisma(): PrismaClient {
  shared ??= createPrisma();
  return shared;
}
