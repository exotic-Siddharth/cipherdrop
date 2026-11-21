/**
 * The API's runtime database role (ops-7): rows only, never the schema. docker-compose.prod.yml runs the
 * migrations in a one-shot `migrate` service as the database owner, which then calls provisionRuntimeRole(); the API
 * itself connects as the runtime role. So a SQL injection, were one ever to appear (every raw query is a tagged
 * template today), could read and change rows, but not change the schema, read the server's files or run programs
 * through the database (COPY ... TO PROGRAM needs a superuser, which the owner the postgres image creates is).
 *
 * The role gets LOGIN and nothing else at role level, USAGE on the schema (never CREATE), SELECT, INSERT, UPDATE and
 * DELETE on its tables, USAGE and SELECT on its sequences, and the same through default privileges on whatever later
 * migrations create, but nothing on _prisma_migrations (the migration history). Run again, it is idempotent and sets
 * the password anew (rotation: change it in the environment, re-run `migrate`, restart the API).
 *
 * The password is sent as a SCRAM-SHA-256 verifier computed here, as psql's \password does: the server stores it
 * as it is and never sees the password, so it cannot reach the server's statement log either.
 */
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';

/** An unquoted Postgres identifier: what a role or schema name here may be. */
export const IDENTIFIER_RE = /^[a-z_][a-z0-9_]{0,62}$/;
/**
 * URL-safe ASCII, because compose writes the password into DATABASE_URL; SASLprep (RFC 4013), which Postgres
 * applies before hashing, leaves such a password unchanged, so the verifier below is what the server computes.
 */
export const RUNTIME_PASSWORD_RE = /^[A-Za-z0-9._~-]{24,128}$/;
const PLACEHOLDER_RE = /dev-only|test-only|change-me/i;

const SCRAM_ITERATIONS = 4096;

/** A SCRAM-SHA-256 verifier in Postgres's format (RFC 5802 / RFC 7677): SCRAM-SHA-256$<i>:<salt>$<StoredKey>:<ServerKey>. */
export function scramSha256Verifier(
  password: string,
  salt: Buffer = randomBytes(16),
  iterations: number = SCRAM_ITERATIONS,
): string {
  const salted = pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const clientKey = createHmac('sha256', salted).update('Client Key').digest();
  const storedKey = createHash('sha256').update(clientKey).digest();
  const serverKey = createHmac('sha256', salted).update('Server Key').digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}

export interface RuntimeRoleOptions {
  role: string;
  password: string;
  /** The schema the API's tables live in (DATABASE_URL ?schema=, default public). */
  schema: string;
}

/** Throws (naming the variable, never its value) unless the options are safe to use. */
export function checkRuntimeRoleOptions(opts: RuntimeRoleOptions): void {
  // pg_ names are reserved for Postgres's own roles.
  if (!IDENTIFIER_RE.test(opts.role) || opts.role.startsWith('pg_')) {
    throw new Error(`DB_RUNTIME_ROLE must match ${IDENTIFIER_RE} and not start with pg_`);
  }
  if (!IDENTIFIER_RE.test(opts.schema)) throw new Error(`the schema must match ${IDENTIFIER_RE}`);
  if (!RUNTIME_PASSWORD_RE.test(opts.password)) {
    throw new Error(
      'DB_RUNTIME_PASSWORD must be 24 to 128 URL-safe characters (A-Z a-z 0-9 . _ ~ -), e.g. openssl rand -hex 24',
    );
  }
  if (PLACEHOLDER_RE.test(opts.password)) {
    throw new Error('DB_RUNTIME_PASSWORD is still a placeholder');
  }
}

/**
 * Create or update the runtime role, connected as the owner of the schema's tables (the role that ran the
 * migrations: default privileges apply to objects that role creates). One transaction: all or nothing.
 */
export async function provisionRuntimeRole(
  prisma: PrismaClient,
  opts: RuntimeRoleOptions,
): Promise<void> {
  checkRuntimeRoleOptions(opts);
  const role = `"${opts.role}"`;
  const schema = `"${opts.schema}"`;
  // Base64 and the format's own "$" and ":" only: nothing that could end the string literal.
  const verifier = scramSha256Verifier(opts.password);
  if (!/^[A-Za-z0-9+/=$:-]+$/.test(verifier)) throw new Error('unexpected verifier format');
  const [{ database }] = await prisma.$queryRaw<{ database: string }[]>`
    SELECT current_database() AS "database"`;
  const dml = 'SELECT, INSERT, UPDATE, DELETE';
  await prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(
      `DO $$ BEGIN
         IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${opts.role}') THEN CREATE ROLE ${role}; END IF;
       END $$`,
    );
    await tx.$executeRawUnsafe(
      `ALTER ROLE ${role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '${verifier}'`,
    );
    await tx.$executeRawUnsafe(
      `GRANT CONNECT ON DATABASE "${database.replace(/"/g, '""')}" TO ${role}`,
    );
    // USAGE only: never CREATE, whatever an earlier grant said.
    await tx.$executeRawUnsafe(`REVOKE ALL ON SCHEMA ${schema} FROM ${role}`);
    await tx.$executeRawUnsafe(`GRANT USAGE ON SCHEMA ${schema} TO ${role}`);
    await tx.$executeRawUnsafe(`REVOKE ALL ON ALL TABLES IN SCHEMA ${schema} FROM ${role}`);
    await tx.$executeRawUnsafe(`GRANT ${dml} ON ALL TABLES IN SCHEMA ${schema} TO ${role}`);
    await tx.$executeRawUnsafe(
      `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${schema} TO ${role}`,
    );
    await tx.$executeRawUnsafe(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA ${schema} GRANT ${dml} ON TABLES TO ${role}`,
    );
    await tx.$executeRawUnsafe(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA ${schema} GRANT USAGE, SELECT ON SEQUENCES TO ${role}`,
    );
    // The migration history is the owner's alone. It exists once `migrate deploy` has run, which comes first.
    await tx.$executeRawUnsafe(
      `DO $$ BEGIN
         IF to_regclass('${opts.schema}._prisma_migrations') IS NOT NULL THEN
           REVOKE ALL ON TABLE ${schema}."_prisma_migrations" FROM ${role};
         END IF;
       END $$`,
    );
  });
}
