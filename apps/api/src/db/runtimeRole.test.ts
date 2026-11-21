/**
 * The API's runtime database role (ops-7) against the real test Postgres, in this lane's schema: what
 * provisionRuntimeRole() grants is exactly rows (read, insert, change, delete) of the API's tables, now and after
 * later migrations, and nothing on the schema, the migration history or the server. Connecting as the role proves
 * that the client-side SCRAM verifier is the one the server computes. Roles are cluster-wide, so each run uses a
 * role of its own and drops it again.
 */
import { randomBytes } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { testDatabaseUrl, testSchema } from '../../test/config';
import { createUserRecord } from '../../test/factories';
import {
  checkOwnerUrl,
  checkRuntimeRoleOptions,
  provisionRuntimeRole,
  scramSha256Verifier,
} from './runtimeRole';

const schema = testSchema();
const role = `cd_runtime_${randomBytes(4).toString('hex')}`;
const newPassword = () => randomBytes(24).toString('hex');
let password = newPassword();

const owner = new PrismaClient({ datasourceUrl: testDatabaseUrl(schema) });
const clients: PrismaClient[] = [];

/** A client connected as the runtime role (with `pw`). */
function asRuntime(pw: string = password): PrismaClient {
  const url = new URL(testDatabaseUrl(schema));
  url.username = role;
  url.password = pw;
  const client = new PrismaClient({ datasourceUrl: url.toString(), errorFormat: 'minimal' });
  clients.push(client);
  return client;
}

/** The Postgres error code (SQLSTATE) a raw statement fails with, or 'ok'. */
async function sqlState(client: PrismaClient, sql: string): Promise<string> {
  try {
    await client.$executeRawUnsafe(sql);
    return 'ok';
  } catch (err) {
    const meta = (err as { meta?: { code?: string } }).meta;
    return meta?.code ?? (err as Error).message;
  }
}

beforeAll(async () => {
  await provisionRuntimeRole(owner, { role, password, schema });
});

afterAll(async () => {
  for (const c of clients) await c.$disconnect();
  await owner.$executeRawUnsafe(`DROP OWNED BY "${role}"`);
  await owner.$executeRawUnsafe(`DROP ROLE IF EXISTS "${role}"`);
  await owner.$disconnect();
});

describe('provisionRuntimeRole', () => {
  it('creates a login role with no role-level powers, whose password is a SCRAM-SHA-256 verifier', async () => {
    const [row] = await owner.$queryRaw<Record<string, unknown>[]>`
      SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, rolbypassrls,
             left(rolpassword, 19) AS "scheme"
      FROM pg_authid WHERE rolname = ${role}`;
    expect(row).toEqual({
      rolcanlogin: true,
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolinherit: false,
      rolreplication: false,
      rolbypassrls: false,
      scheme: 'SCRAM-SHA-256$4096:',
    });
    // The server accepts the password: the verifier computed here is the one it would compute.
    const [me] = await asRuntime().$queryRaw<{ user: string }[]>`SELECT current_user AS "user"`;
    expect(me?.user).toBe(role);
    await expect(asRuntime(newPassword()).$queryRaw`SELECT 1`).rejects.toThrow();
  });

  it('reads and changes rows through the Prisma client, as the API does', async () => {
    const app = asRuntime();
    const user = await createUserRecord(app);
    await app.user.update({ where: { id: user.id }, data: { failedLoginCount: 1 } });
    const locked = await app.$transaction(
      (tx) =>
        tx.$queryRaw<{ id: string }[]>`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR UPDATE`,
    );
    expect(locked).toEqual([{ id: user.id }]);
    await app.user.delete({ where: { id: user.id } });
    expect(await app.user.count({ where: { id: user.id } })).toBe(0);
  });

  it('has exactly SELECT, INSERT, UPDATE and DELETE on every table but the migration history', async () => {
    const tables = await owner.$queryRaw<{ name: string }[]>`
      SELECT quote_ident(table_schema) || '.' || quote_ident(table_name) AS "name"
      FROM information_schema.tables WHERE table_schema = ${schema} AND table_type = 'BASE TABLE'`;
    expect(tables.length).toBeGreaterThan(5);
    for (const { name } of tables) {
      const [p] = await owner.$queryRaw<Record<string, boolean>[]>`
        SELECT has_table_privilege(${role}, ${name}, 'SELECT') AS "select",
               has_table_privilege(${role}, ${name}, 'INSERT') AS "insert",
               has_table_privilege(${role}, ${name}, 'UPDATE') AS "update",
               has_table_privilege(${role}, ${name}, 'DELETE') AS "delete",
               has_table_privilege(${role}, ${name}, 'TRUNCATE') AS "truncate",
               has_table_privilege(${role}, ${name}, 'REFERENCES') AS "references",
               has_table_privilege(${role}, ${name}, 'TRIGGER') AS "trigger"`;
      const dml = !name.endsWith('_prisma_migrations');
      expect(p, name).toEqual({
        select: dml,
        insert: dml,
        update: dml,
        delete: dml,
        truncate: false,
        references: false,
        trigger: false,
      });
    }
    const [s] = await owner.$queryRaw<{ usage: boolean; create: boolean }[]>`
      SELECT has_schema_privilege(${role}, ${schema}, 'USAGE') AS "usage",
             has_schema_privilege(${role}, ${schema}, 'CREATE') AS "create"`;
    expect(s).toEqual({ usage: true, create: false });
  });

  it('cannot change the schema, read the migration history or reach the server', async () => {
    const app = asRuntime();
    const q = (t: string) => `"${schema}"."${t}"`;
    // 42501 insufficient_privilege; ALTER and DROP of another role's table also fail with it.
    expect(await sqlState(app, `CREATE TABLE ${q('cd_runtime_probe')} (id int)`)).toBe('42501');
    expect(await sqlState(app, `ALTER TABLE ${q('User')} ADD COLUMN "x" int`)).toBe('42501');
    expect(await sqlState(app, `DROP TABLE ${q('AuditEvent')}`)).toBe('42501');
    expect(await sqlState(app, `TRUNCATE ${q('User')}`)).toBe('42501');
    expect(await sqlState(app, `SELECT * FROM ${q('_prisma_migrations')}`)).toBe('42501');
    expect(await sqlState(app, `COPY (SELECT 1) TO PROGRAM 'id'`)).toBe('42501');
    expect(await sqlState(app, `SELECT pg_read_file('/etc/passwd')`)).toBe('42501');
    expect(await sqlState(app, `CREATE ROLE cd_runtime_escalate`)).toBe('42501');
  });

  it('gives tables that later migrations create the same rights (default privileges)', async () => {
    const table = `"${schema}"."cd_runtime_later_${randomBytes(3).toString('hex')}"`;
    await owner.$executeRawUnsafe(`CREATE TABLE ${table} (id int)`);
    try {
      const app = asRuntime();
      expect(await sqlState(app, `INSERT INTO ${table} VALUES (1)`)).toBe('ok');
      expect(await sqlState(app, `DELETE FROM ${table}`)).toBe('ok');
      expect(await sqlState(app, `DROP TABLE ${table}`)).toBe('42501');
    } finally {
      await owner.$executeRawUnsafe(`DROP TABLE ${table}`);
    }
  });

  it('is idempotent and sets the password anew (rotation)', async () => {
    const old = password;
    password = newPassword();
    await provisionRuntimeRole(owner, { role, password, schema });
    await provisionRuntimeRole(owner, { role, password, schema });
    await expect(asRuntime(old).$queryRaw`SELECT 1`).rejects.toThrow();
    await expect(asRuntime().$queryRaw`SELECT 1`).resolves.toBeDefined();
  });
});

describe('provisionRuntimeRole on a role that already existed with more power', () => {
  const other = `cd_runtime_${randomBytes(4).toString('hex')}`;
  const group = `cd_runtime_group_${randomBytes(4).toString('hex')}`;
  afterAll(async () => {
    for (const r of [other, group]) {
      await owner.$executeRawUnsafe(`DROP OWNED BY "${r}"`).catch(() => {});
      await owner.$executeRawUnsafe(`DROP ROLE IF EXISTS "${r}"`);
    }
  });

  it('takes role-level powers away (as a superuser owner) and refuses a role that is a member of another', async () => {
    await owner.$executeRawUnsafe(`CREATE ROLE "${other}" LOGIN CREATEDB CREATEROLE BYPASSRLS`);
    await provisionRuntimeRole(owner, { role: other, password: newPassword(), schema });
    const [row] = await owner.$queryRaw<Record<string, boolean>[]>`
      SELECT rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = ${other}`;
    expect(row).toEqual({ rolcreatedb: false, rolcreaterole: false, rolbypassrls: false });

    await owner.$executeRawUnsafe(`CREATE ROLE "${group}"`);
    await owner.$executeRawUnsafe(`GRANT "${group}" TO "${other}"`);
    await expect(
      provisionRuntimeRole(owner, { role: other, password: newPassword(), schema }),
    ).rejects.toThrow(/member of another role/);
  });
});

describe('checkRuntimeRoleOptions', () => {
  const ok = { role: 'cipherdrop_app', password: 'a'.repeat(48), schema: 'public' };

  it.each([
    [{ role: 'Robert"; DROP TABLE x; --' }, /DB_RUNTIME_ROLE/],
    [{ role: 'pg_signal_backend' }, /DB_RUNTIME_ROLE/],
    [{ schema: 'public; DROP' }, /schema/],
    [{ password: 'short' }, /DB_RUNTIME_PASSWORD/],
    [{ password: `${'a'.repeat(30)}@host` }, /DB_RUNTIME_PASSWORD/],
    [{ password: `${'a'.repeat(30)}'quote` }, /DB_RUNTIME_PASSWORD/],
    [{ password: 'change-me-generate-with-openssl-rand-hex-24' }, /placeholder/],
  ])('refuses %j', (bad, message) => {
    expect(() => checkRuntimeRoleOptions({ ...ok, ...bad })).toThrow(message);
  });

  it('accepts a generated password', () => {
    expect(() => checkRuntimeRoleOptions({ ...ok, password: newPassword() })).not.toThrow();
  });
});

describe('checkOwnerUrl', () => {
  const template = 'change-me-generate-with-openssl-rand-hex-24';

  it.each([
    [undefined, /DATABASE_URL must be set/],
    ['', /DATABASE_URL must be set/],
    ['not a url', /DATABASE_URL must be set/],
    [`postgresql://cipherdrop:${template}@postgres:5432/cipherdrop?schema=public`, /placeholder/],
    ['postgresql://cipherdrop:cipherdrop-dev-only@127.0.0.1:5432/cipherdrop', /placeholder/],
    ['postgresql://cipherdrop:%63hange-me-x@postgres:5432/cipherdrop', /placeholder/],
    ['postgresql://cipherdrop:%E0%A4%A@postgres:5432/cipherdrop', /percent-encoding/],
  ])('refuses %j, naming DATABASE_URL and not the value', (url, message) => {
    expect(() => checkOwnerUrl(url)).toThrow(message);
    expect(() => checkOwnerUrl(url)).toThrow(/DATABASE_URL/);
    try {
      checkOwnerUrl(url);
    } catch (err) {
      expect((err as Error).message).not.toContain(template);
      expect((err as Error).message).not.toContain('dev-only');
    }
  });

  it('accepts an owner URL with a generated password', () => {
    expect(() =>
      checkOwnerUrl(
        `postgresql://cipherdrop:${newPassword()}@postgres:5432/cipherdrop?schema=public`,
      ),
    ).not.toThrow();
  });
});

describe('scramSha256Verifier', () => {
  it('has the format Postgres stores, and never contains the password', () => {
    const pw = newPassword();
    const v = scramSha256Verifier(pw, Buffer.alloc(16, 1));
    expect(v).toMatch(
      /^SCRAM-SHA-256\$4096:[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$/,
    );
    expect(v).not.toContain(pw);
    // A fresh salt every time unless one is given.
    expect(scramSha256Verifier(pw)).not.toBe(scramSha256Verifier(pw));
    expect(scramSha256Verifier(pw, Buffer.alloc(16, 1))).toBe(v);
  });
});
