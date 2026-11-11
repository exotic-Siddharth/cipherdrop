/**
 * Per-app dependency context. createApp(deps) builds one AppContext; route factories receive it, and
 * middleware reads it with getCtx(req) (it lives on app.locals.ctx).
 *
 * Library code that is not per-app (jwt secret, Redis KEY_PREFIX) reads the global `env`; per-app limits
 * (quotas, expiry ceilings, grant TTL...) should be read from ctx.env so tests can override them via
 * createApp({ env: { ANON_MAX_DROP_BYTES: 1000 } }).
 */
import type { PrismaClient } from '@prisma/client';
import type { Request } from 'express';
import type { Redis } from 'ioredis';
import { env as globalEnv, type Env } from './config/env';
import { getPrisma } from './db/prisma';
import { logger as defaultLogger, type Logger } from './lib/logger';
import {
  createRateLimitFactory,
  type RateLimitFactory,
  type RateLimitsConfig,
} from './lib/rateLimit';
import { getRedis } from './lib/redis';
import { createAuditService, type AuditService } from './modules/audit/service';
import { getDefaultStorage, type StorageDriver } from './storage';

export interface AppDeps {
  prisma?: PrismaClient;
  redis?: Redis;
  storage?: StorageDriver;
  /** Clock used by handlers (tests inject a fixed or shifted clock). */
  now?: () => Date;
  /** Override env RATE_LIMITS_ENABLED: all on/off, or per limiter name (R10). */
  rateLimits?: RateLimitsConfig;
  logger?: Logger;
  /** Per-app env overrides (merged over the global env). */
  env?: Partial<Env>;
}

export interface AppContext {
  env: Env;
  prisma: PrismaClient;
  redis: Redis;
  storage: StorageDriver;
  now: () => Date;
  logger: Logger;
  audit: AuditService;
  /** Build a rate-limit middleware bound to this app's Redis and rateLimits config. */
  rateLimit: RateLimitFactory;
}

export function createContext(deps: AppDeps = {}): AppContext {
  const env: Env = { ...globalEnv, ...deps.env };
  const prisma = deps.prisma ?? getPrisma();
  const redis = deps.redis ?? getRedis();
  return {
    env,
    prisma,
    redis,
    storage: deps.storage ?? getDefaultStorage(),
    now: deps.now ?? (() => new Date()),
    logger: deps.logger ?? defaultLogger,
    audit: createAuditService(prisma),
    rateLimit: createRateLimitFactory({
      redis,
      keyPrefix: globalEnv.KEY_PREFIX,
      enabledByDefault: env.RATE_LIMITS_ENABLED,
      overrides: deps.rateLimits,
      logger: deps.logger ?? defaultLogger,
    }),
  };
}

/** The AppContext of the app handling this request. */
export function getCtx(req: Request): AppContext {
  const ctx = (req.app.locals as { ctx?: AppContext }).ctx;
  if (!ctx) throw new Error('AppContext missing: mount routes on an app created by createApp()');
  return ctx;
}
