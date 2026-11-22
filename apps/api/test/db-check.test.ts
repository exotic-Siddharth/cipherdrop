/**
 * The schema drift check (scripts/db-check.ts, `npm run db:check`): its safety checks on SHADOW_DATABASE_URL, and a
 * real run against this lane's Postgres server with the repository's migrations, once unchanged and once with an index
 * added to a copy of schema.prisma that no migration creates.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';
import { afterAll, describe, expect, it } from 'vitest';
import {
  checkDrift,
  DEFAULT_SHADOW_DATABASE_URL,
  maintenanceUrl,
  shadowDatabaseName,
} from '../scripts/db-check';
import { TEST_DB_NAME, testSchema, testServerUrl } from './config';

const apiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schemaFile = path.join(apiRoot, 'prisma', 'schema.prisma');
const migrationsDir = path.join(apiRoot, 'prisma', 'migrations');

describe('shadowDatabaseName', () => {
  it('accepts a postgresql:// URL whose database name ends in _shadow', () => {
    expect(shadowDatabaseName(DEFAULT_SHADOW_DATABASE_URL)).toBe('cipherdrop_shadow');
    expect(shadowDatabaseName('postgres://u:p@db:5432/ci_shadow?schema=public')).toBe('ci_shadow');
  });

  it('refuses any other database, because prisma migrate diff wipes it', () => {
    for (const url of [
      'postgresql://u:p@localhost:55433/cipherdrop',
      'postgresql://u:p@localhost:55433/cipherdrop_test',
      'postgresql://u:p@localhost:55433/shadow',
      'postgresql://u:p@localhost:55433/Prod_shadow',
      'postgresql://u:p@localhost:55433/x%22_shadow',
      'postgresql://u:p@localhost:55433/',
    ]) {
      expect(() => shadowDatabaseName(url), url).toThrow(/ends in _shadow/);
    }
    expect(() => shadowDatabaseName('mysql://u:p@localhost/x_shadow')).toThrow(/postgresql:\/\//);
    expect(() => shadowDatabaseName('not a url')).toThrow(/not a URL/);
  });

  it('refuses the database DATABASE_URL points at', () => {
    const url = 'postgresql://u:p@localhost:55433/app_shadow';
    expect(() =>
      shadowDatabaseName(url, 'postgresql://u:p@localhost:55433/app_shadow?schema=public'),
    ).toThrow(/must not be the database of DATABASE_URL/);
    expect(shadowDatabaseName(url, 'postgresql://u:p@localhost:55433/app?schema=public')).toBe(
      'app_shadow',
    );
  });

  it("runs CREATE DATABASE from the same server's maintenance database", () => {
    expect(maintenanceUrl('postgresql://u:p@db:5432/ci_shadow?schema=public')).toBe(
      'postgresql://u:p@db:5432/postgres',
    );
  });
});

describe('checkDrift against Postgres', () => {
  // One shadow database per lane, so parallel lanes on one server never share it.
  const shadowName = `${TEST_DB_NAME}_${testSchema().slice(0, 30)}_shadow`.replace(/__+/g, '_');
  const shadowUrl = `${testServerUrl()}/${shadowName}`;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'db-check-'));

  afterAll(async () => {
    fs.rmSync(tmp, { recursive: true, force: true });
    const admin = new PrismaClient({ datasourceUrl: maintenanceUrl(shadowUrl) });
    try {
      // shadowName matches the script's [a-z0-9_] pattern: safe to interpolate.
      await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${shadowName}" WITH (FORCE)`);
    } finally {
      await admin.$disconnect();
    }
  });

  it('passes when the migrations build schema.prisma (the committed state)', async () => {
    const log: string[] = [];
    const code = await checkDrift({ shadowUrl, log: (l) => log.push(l) });
    expect(log.join('\n')).toContain('no drift');
    expect(code).toBe(0);
  });

  it('fails with exit code 2 on an index that schema.prisma declares and no migration creates', async () => {
    const schema = fs.readFileSync(schemaFile, 'utf8');
    const anchor = '  @@index([dropId, expiresAt])\n';
    expect(schema).toContain(anchor);
    const drifted = path.join(tmp, 'schema.prisma');
    fs.writeFileSync(drifted, schema.replace(anchor, `${anchor}  @@index([expiresAt])\n`));

    const log: string[] = [];
    const code = await checkDrift({
      schema: drifted,
      migrations: migrationsDir,
      shadowUrl,
      log: (l) => log.push(l),
    });
    expect(code).toBe(2);
    expect(log.join('\n')).toContain('DRIFT');
    expect(log.join('\n')).toContain('CREATE INDEX "DownloadGrant_expiresAt_idx"');
  });

  it('refuses to run against a database that does not end in _shadow, before touching it', async () => {
    const log: string[] = [];
    const code = await checkDrift({
      shadowUrl: `${testServerUrl()}/${TEST_DB_NAME}`,
      log: (l) => log.push(l),
    });
    expect(code).toBe(1);
    expect(log.join('\n')).toMatch(/ends in _shadow/);
  });
});
