/**
 * API entry point: dev `tsx watch src/index.ts`, prod `node dist/index.js` (tsup bundle).
 * Graceful shutdown (spec section 15): stop accepting connections, stop the cleanup scheduler, then
 * disconnect Prisma and Redis. Windows never delivers SIGTERM, so SIGINT is handled too (R21).
 */
import type { Server } from 'node:http';
import { createApp } from './app';
import { env } from './config/env';
import type { AppContext } from './context';
import { startCleanupScheduler, type CleanupScheduler } from './jobs/cleanup';
import { installFatalHandlers } from './lib/fatalHandlers';
import { logger } from './lib/logger';
import { getRedis } from './lib/redis';

async function main(): Promise<void> {
  installFatalHandlers(process, logger);
  // Fail fast with ONE readable error when Redis is down (the rate limiters load their scripts at start-up).
  await getRedis().ping();
  const app = createApp();
  const ctx = app.locals.ctx as AppContext;

  await ctx.prisma.$connect();
  await ctx.storage.init();

  // Express 5 also passes a listen error (EADDRINUSE...) to this callback: only log "listening" on success.
  const server: Server = app.listen(env.API_PORT, (err?: Error) => {
    if (err) return;
    logger.info({ port: env.API_PORT, storage: env.STORAGE_DRIVER }, 'CipherDrop API listening');
  });
  server.on('error', (err) => {
    logger.fatal({ err }, 'HTTP server error');
    process.exit(1);
  });

  const scheduler: CleanupScheduler = startCleanupScheduler(ctx);

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'shutting down');
    const force = setTimeout(() => process.exit(1), 10_000);
    force.unref();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeIdleConnections();
    });
    await scheduler.stop();
    await ctx.prisma.$disconnect();
    ctx.redis.disconnect();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((err: unknown) => {
  logger.fatal({ err }, 'API failed to start');
  process.exit(1);
});
