/**
 * createTestApp(): an app wired to the test database, the test Redis DB and a fresh temp local storage dir.
 * Always `await t.close()` in afterAll so no connection keeps the worker alive.
 */
import type { PrismaClient } from '@prisma/client';
import type { Express } from 'express';
import type { Redis } from 'ioredis';
import { createApp } from '../src/app';
import { env } from '../src/config/env';
import type { AppContext, AppDeps } from '../src/context';
import { createPrisma } from '../src/db/prisma';
import { createRedis } from '../src/lib/redis';
import { createStorage, type StorageDriver } from '../src/storage';
import { removeDir, tempStorageDir } from './storage';

export interface TestApp {
  app: Express;
  ctx: AppContext;
  prisma: PrismaClient;
  redis: Redis;
  storage: StorageDriver;
  storageDir: string;
  close(): Promise<void>;
}

export async function createTestApp(deps: AppDeps = {}): Promise<TestApp> {
  const prisma = deps.prisma ?? createPrisma(env.DATABASE_URL);
  const redis = deps.redis ?? createRedis(env.REDIS_URL);
  const storageDir = tempStorageDir();
  const storage =
    deps.storage ?? createStorage({ ...env, STORAGE_DRIVER: 'local', STORAGE_DIR: storageDir });
  await storage.init();
  const app = createApp({ ...deps, prisma, redis, storage });
  const ctx = app.locals.ctx as AppContext;
  return {
    app,
    ctx,
    prisma,
    redis,
    storage,
    storageDir,
    async close() {
      if (!deps.prisma) await prisma.$disconnect();
      if (!deps.redis) redis.disconnect();
      await removeDir(storageDir);
    },
  };
}
