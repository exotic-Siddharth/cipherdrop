/**
 * One-shot CLI (dist/provision-runtime-role.js): create or update the API's runtime database role, see
 * runtimeRole.ts. deploy/api-entrypoint.sh `migrate` runs it after `prisma migrate deploy`, in the compose stack's
 * `migrate` service. Reads only:
 *   DATABASE_URL         the owner that ran the migrations (its ?schema= is the schema to grant on, default public)
 *   DB_RUNTIME_ROLE      the role the API connects as, e.g. cipherdrop_app
 *   DB_RUNTIME_PASSWORD  its password (the API's DATABASE_URL carries the same one)
 * Not the API's config/env.ts: this container holds the owner's credentials and none of the API's secrets.
 * Logs one JSON line; a failure names the error class and code only (a Prisma message can carry the statement).
 */
import { PrismaClient } from '@prisma/client';
import { pino } from 'pino';
import { checkOwnerUrl, provisionRuntimeRole } from './runtimeRole';

const log = pino({ base: { service: 'migrate' } });

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL ?? '';
  // Refuses the template's placeholder owner password too: nothing else checks it (see checkOwnerUrl).
  checkOwnerUrl(url);
  const role = process.env.DB_RUNTIME_ROLE ?? '';
  const schema = new URL(url).searchParams.get('schema') ?? 'public';
  const prisma = new PrismaClient({ datasourceUrl: url, errorFormat: 'minimal' });
  try {
    await provisionRuntimeRole(prisma, {
      role,
      password: process.env.DB_RUNTIME_PASSWORD ?? '',
      schema,
    });
  } finally {
    await prisma.$disconnect();
  }
  log.info({ role, schema }, 'runtime database role is up to date (DML only)');
}

main().catch((err: unknown) => {
  const e = err as { name?: string; code?: string; message?: string };
  // Our own checks name a variable, never a value; Prisma's errors are other classes and are not printed.
  const ours = e.name === 'Error';
  log.fatal(
    { errName: e.name, errCode: e.code, ...(ours ? { reason: e.message } : {}) },
    'could not provision the runtime database role',
  );
  process.exit(1);
});
