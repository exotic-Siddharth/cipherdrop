/**
 * Last-resort handlers (index.ts). An unhandled rejection (for example rate-limit-redis loading its Lua script
 * while Redis is down) or an uncaught exception is a bug or a broken dependency: log it as one structured
 * fatal line and exit non-zero so the supervisor restarts the process. Never swallow it and keep serving.
 */
import type { EventEmitter } from 'node:events';
import type { Logger } from './logger';

export function installFatalHandlers(
  proc: Pick<EventEmitter, 'on'>,
  logger: Pick<Logger, 'fatal'>,
  exit: (code: number) => void = (code) => process.exit(code),
): void {
  const toErr = (reason: unknown) =>
    reason instanceof Error ? reason : { message: String(reason) };
  proc.on('unhandledRejection', (reason: unknown) => {
    logger.fatal({ err: toErr(reason) }, 'unhandled promise rejection');
    exit(1);
  });
  proc.on('uncaughtException', (err: unknown) => {
    logger.fatal({ err: toErr(err) }, 'uncaught exception');
    exit(1);
  });
}
