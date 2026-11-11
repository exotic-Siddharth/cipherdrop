/**
 * Boots the e2e API (spec section 14, R2): creates cipherdrop_e2e when missing, applies every migration,
 * wipes all rows, the Redis DB and the blob directory, then starts the real API entry point.
 *
 * Playwright starts its webServers BEFORE any globalSetup, and the API needs the database at boot, so the
 * preparation lives here. Every `npm run e2e` therefore starts from an empty, fully migrated database.
 * Run as: node --import tsx apps/web/e2e/support/start-api.ts (cwd = repo root; env from playwright.config.ts).
 */
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';
import { Redis } from 'ioredis';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..', '..', '..');
const apiRoot = path.join(repoRoot, 'apps', 'api');

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;
if (!databaseUrl || !redisUrl)
  throw new Error('start-api: DATABASE_URL and REDIS_URL are required');

const target = new URL(databaseUrl);
const dbName = decodeURIComponent(target.pathname.slice(1));
if (dbName !== 'cipherdrop_e2e') {
  throw new Error(`start-api refuses to wipe database "${dbName}" (only cipherdrop_e2e)`);
}

async function ensureDatabase(): Promise<void> {
  const admin = new URL(databaseUrl as string);
  admin.pathname = '/postgres';
  admin.search = '';
  const prisma = new PrismaClient({ datasourceUrl: admin.toString() });
  try {
    const rows = await prisma.$queryRaw<{ datname: string }[]>`
      SELECT datname FROM pg_database WHERE datname = ${dbName}`;
    if (rows.length === 0) await prisma.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
  } finally {
    await prisma.$disconnect();
  }
}

function migrate(): void {
  const prismaCli = require.resolve('prisma/build/index.js');
  execFileSync(
    process.execPath,
    [prismaCli, 'migrate', 'deploy', '--schema', path.join(apiRoot, 'prisma', 'schema.prisma')],
    { cwd: apiRoot, env: process.env, stdio: 'pipe' },
  );
}

async function wipeRows(): Promise<void> {
  const prisma = new PrismaClient({ datasourceUrl: databaseUrl });
  try {
    const rows = await prisma.$queryRaw<{ tablename: string }[]>`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`;
    if (rows.length > 0) {
      const tables = rows.map((r) => `"public"."${r.tablename}"`).join(', ');
      await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${tables} RESTART IDENTITY CASCADE`);
    }
  } finally {
    await prisma.$disconnect();
  }
}

async function wipeRedis(): Promise<void> {
  const redis = new Redis(redisUrl as string, { lazyConnect: true });
  try {
    await redis.connect();
    await redis.flushdb();
  } finally {
    redis.disconnect();
  }
}

await ensureDatabase();
migrate();
await wipeRows();
await wipeRedis();
const storageDir = path.resolve(apiRoot, process.env.STORAGE_DIR ?? './data/e2e-blobs');
if (path.basename(storageDir) !== 'e2e-blobs') throw new Error('start-api: unexpected STORAGE_DIR');
fs.rmSync(storageDir, { recursive: true, force: true, maxRetries: 5 });

await import('../../../api/src/index');
