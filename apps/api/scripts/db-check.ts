/**
 * Schema drift check (`npm run db:check`, CI integration job): do the migrations in prisma/migrations build exactly
 * the datamodel of prisma/schema.prisma?
 *
 * Every test database is built with `prisma migrate deploy`, while the client is generated from schema.prisma. A
 * missing column fails the tests at once (the client queries it), but an index, unique constraint, default or
 * foreign-key rule added to schema.prisma without a migration passes everything and then differs in production.
 * `prisma migrate diff --from-migrations ... --to-schema-datamodel ... --exit-code` replays the migrations into a
 * scratch database (the shadow database) and compares the result with the schema.
 *
 * Exit codes: 0 no drift; 2 drift (the SQL that would close the gap is printed); 1 the check could not run.
 *
 *   npm run db:check -w @cipherdrop/api [-- --schema <schema.prisma> --migrations <dir>]
 *
 * SHADOW_DATABASE_URL (default postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_shadow, the dev compose
 * server) names that scratch database. Prisma drops everything in it, so its name must end in `_shadow` and differ
 * from DATABASE_URL's: a mistyped URL cannot point the check at real data. It is created when missing and left in
 * place for the next run.
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';

const require = createRequire(import.meta.url);
const apiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const DEFAULT_SHADOW_DATABASE_URL =
  'postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_shadow';
/** A plain lower-case identifier that ends in _shadow (so CREATE DATABASE needs no escaping either). */
const SHADOW_NAME_RE = /^[a-z][a-z0-9_]{0,55}_shadow$/;

function databaseName(url: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${label} is not a URL`);
  }
  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
    throw new Error(`${label} must be a postgresql:// URL`);
  }
  return decodeURIComponent(parsed.pathname.replace(/^\//, ''));
}

/**
 * The shadow database's name, after the safety checks: a postgresql:// URL whose database name ends in `_shadow`
 * and is not the database of `databaseUrl` (the application's DATABASE_URL, when set).
 */
export function shadowDatabaseName(shadowUrl: string, databaseUrl?: string): string {
  const name = databaseName(shadowUrl, 'SHADOW_DATABASE_URL');
  if (!SHADOW_NAME_RE.test(name)) {
    throw new Error(
      `SHADOW_DATABASE_URL must name a scratch database whose name ends in _shadow (got "${name}"): ` +
        'prisma migrate diff drops everything in it',
    );
  }
  if (databaseUrl) {
    const app = new URL(databaseUrl);
    const shadow = new URL(shadowUrl);
    if (app.host === shadow.host && databaseName(databaseUrl, 'DATABASE_URL') === name) {
      throw new Error('SHADOW_DATABASE_URL must not be the database of DATABASE_URL');
    }
  }
  return name;
}

/** The same server's `postgres` maintenance database, from which CREATE DATABASE runs. */
export function maintenanceUrl(shadowUrl: string): string {
  const url = new URL(shadowUrl);
  url.pathname = '/postgres';
  url.search = '';
  return url.toString();
}

/** CREATE DATABASE <name> unless the server has it (safe when two runs race). */
export async function ensureShadowDatabase(shadowUrl: string, name: string): Promise<void> {
  const admin = new PrismaClient({ datasourceUrl: maintenanceUrl(shadowUrl) });
  try {
    const rows = await admin.$queryRaw<{ datname: string }[]>`
      SELECT datname FROM pg_database WHERE datname = ${name}`;
    if (rows.length > 0) return;
    try {
      // An identifier cannot be a bind parameter; `name` matched SHADOW_NAME_RE ([a-z0-9_] only).
      await admin.$executeRawUnsafe(`CREATE DATABASE "${name}"`);
    } catch (err) {
      if (!/42P04|already exists/i.test(err instanceof Error ? err.message : String(err)))
        throw err;
    }
  } finally {
    await admin.$disconnect();
  }
}

export interface DriftResult {
  /** 0 no drift, 2 drift, anything else: the check failed. */
  status: number;
  stdout: string;
  stderr: string;
}

/** `prisma migrate diff --from-migrations <dir> --to-schema-datamodel <schema> --exit-code`. */
export function migrateDiff(opts: {
  schema: string;
  migrations: string;
  shadowUrl: string;
}): DriftResult {
  const prismaCli = require.resolve('prisma/build/index.js');
  const res = spawnSync(
    process.execPath,
    [
      prismaCli,
      'migrate',
      'diff',
      '--from-migrations',
      opts.migrations,
      '--to-schema-datamodel',
      opts.schema,
      '--shadow-database-url',
      opts.shadowUrl,
      '--script',
      '--exit-code',
    ],
    {
      cwd: apiRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        // The datamodel side takes its Postgres schema (`?schema=`) from the datasource URL, env("DATABASE_URL"):
        // pointed elsewhere (a test lane's schema), it would be compared with migrations replayed into another one.
        DATABASE_URL: opts.shadowUrl,
        CHECKPOINT_DISABLE: '1',
        PRISMA_HIDE_UPDATE_MESSAGE: '1',
      },
    },
  );
  return { status: res.status ?? 1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/** Runs the check and returns the process exit code (0, 1 or 2). */
export async function checkDrift(
  opts: {
    schema?: string;
    migrations?: string;
    shadowUrl?: string;
    databaseUrl?: string;
    log?: (line: string) => void;
  } = {},
): Promise<number> {
  const log = opts.log ?? ((line: string) => process.stdout.write(`${line}\n`));
  const schema = path.resolve(opts.schema ?? path.join(apiRoot, 'prisma', 'schema.prisma'));
  const migrations = path.resolve(opts.migrations ?? path.join(apiRoot, 'prisma', 'migrations'));
  const shadowUrl = opts.shadowUrl ?? DEFAULT_SHADOW_DATABASE_URL;
  try {
    const name = shadowDatabaseName(shadowUrl, opts.databaseUrl);
    await ensureShadowDatabase(shadowUrl, name);
    const res = migrateDiff({ schema, migrations, shadowUrl });
    if (res.status === 0) {
      log(`db:check: no drift, the migrations in ${migrations} build ${schema}`);
      return 0;
    }
    if (res.status === 2) {
      log(`db:check: DRIFT between ${schema} and the migrations in ${migrations}.`);
      log('The SQL that would close the gap (add it as a new migration: npm run db:migrate):');
      log(res.stdout.trimEnd());
      return 2;
    }
    log(`db:check: prisma migrate diff failed (exit ${res.status})`);
    log((res.stderr || res.stdout).trimEnd());
    return 1;
  } catch (err) {
    log(`db:check: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: { schema: { type: 'string' }, migrations: { type: 'string' } },
    strict: true,
  });
  return checkDrift({
    schema: values.schema,
    migrations: values.migrations,
    shadowUrl: process.env.SHADOW_DATABASE_URL?.trim() || undefined,
    databaseUrl: process.env.DATABASE_URL?.trim() || undefined,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      console.error(err);
      process.exitCode = 1;
    },
  );
}
