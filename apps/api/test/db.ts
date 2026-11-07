/**
 * Test database helpers (S3, R2). `setupTestDatabase(schema)` creates `cipherdrop_test` if it is missing and
 * applies every migration to the schema with `prisma migrate deploy` (spawned via process.execPath; never npx).
 */
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';
import { TEST_DB_NAME, maintenanceDatabaseUrl, testDatabaseUrl, testSchema } from './config';

const require = createRequire(import.meta.url);
const apiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const prismaSchemaPath = path.join(apiRoot, 'prisma', 'schema.prisma');

function isDuplicateDatabase(err: unknown): boolean {
  const text = err instanceof Error ? err.message : String(err);
  return /42P04|already exists/i.test(text);
}

/** CREATE DATABASE cipherdrop_test unless it exists (safe when two lanes race). */
export async function ensureTestDatabase(): Promise<void> {
  const admin = new PrismaClient({ datasourceUrl: maintenanceDatabaseUrl() });
  try {
    const rows = await admin.$queryRaw<{ datname: string }[]>`
      SELECT datname FROM pg_database WHERE datname = ${TEST_DB_NAME}`;
    if (rows.length === 0) {
      try {
        await admin.$executeRawUnsafe(`CREATE DATABASE "${TEST_DB_NAME}"`);
      } catch (err) {
        if (!isDuplicateDatabase(err)) throw err;
      }
    }
  } finally {
    await admin.$disconnect();
  }
}

/** `prisma migrate deploy` against cipherdrop_test?schema=<schema> (Prisma creates the schema if needed). */
export function migrateSchema(schema: string = testSchema()): void {
  const prismaCli = require.resolve('prisma/build/index.js');
  try {
    execFileSync(process.execPath, [prismaCli, 'migrate', 'deploy', '--schema', prismaSchemaPath], {
      cwd: apiRoot,
      env: { ...process.env, DATABASE_URL: testDatabaseUrl(schema) },
      stdio: 'pipe',
      encoding: 'utf8',
    });
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message: string };
    throw new Error(
      `prisma migrate deploy failed for schema "${schema}":\n${e.stdout ?? ''}\n${e.stderr ?? e.message}`,
    );
  }
}

/** Ensure the test database exists and the schema is fully migrated. Returns its DATABASE_URL. */
export async function setupTestDatabase(schema: string = testSchema()): Promise<string> {
  await ensureTestDatabase();
  migrateSchema(schema);
  return testDatabaseUrl(schema);
}

/** TRUNCATE every application table of the schema (keeps _prisma_migrations). */
export async function resetTables(
  prisma: PrismaClient,
  schema: string = testSchema(),
): Promise<void> {
  const rows = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = ${schema} AND tablename <> '_prisma_migrations'`;
  if (rows.length === 0) return;
  const tables = rows.map((r) => `"${schema}"."${r.tablename}"`).join(', ');
  await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${tables} RESTART IDENTITY CASCADE`);
}
