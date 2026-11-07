import { $Enums } from '@prisma/client';
import {
  AuditActionSchema,
  DropStatusSchema,
  ReportReasonSchema,
  ReportStatusSchema,
  RoleSchema,
} from '@cipherdrop/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { verifyAuthKey } from '../src/lib/argon2';
import { createTestApp, type TestApp } from './app';
import { testSchema } from './config';
import { resetTables } from './db';
import { TEST_ACCOUNT, createUserRecord } from './factories';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
  await resetTables(t.prisma);
});

afterAll(async () => {
  await t.close();
});

describe('S3 database', () => {
  it('migrations created every table in the test schema', async () => {
    const rows = await t.prisma.$queryRaw<{ tablename: string }[]>`
      SELECT tablename FROM pg_tables WHERE schemaname = ${testSchema()}`;
    expect(rows.map((r) => r.tablename)).toEqual(
      expect.arrayContaining([
        '_prisma_migrations',
        'User',
        'Session',
        'RefreshToken',
        'BackupCode',
        'Drop',
        'DropFile',
        'DropChunk',
        'DownloadGrant',
        'Report',
        'AuditEvent',
      ]),
    );
  });

  it('createUserRecord inserts pre-computed zero-knowledge fields', async () => {
    const user = await createUserRecord(t.prisma);
    expect(user.storageQuotaBytes).toBe(5368709120n);
    expect(user.wrappedAccountKey).toHaveLength(80);
    expect(await verifyAuthKey(user.authKeyHash, TEST_ACCOUNT.authKeyBytes)).toBe(true);
  });

  it('R4 audit.record stores the IP prefix and a UA summary, never the raw address', async () => {
    const user = await createUserRecord(t.prisma);
    await t.ctx.audit.record({
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      req: {
        ip: '203.0.113.9',
        headers: {
          'user-agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
        },
      },
      metadata: { sessionCount: 1 },
    });
    const events = await t.prisma.auditEvent.findMany({ where: { userId: user.id } });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      action: 'LOGIN_SUCCESS',
      ipPrefix: '203.0.113.0/24',
      userAgent: 'Chrome on Windows',
      metadata: { sessionCount: 1 },
    });
  });

  it('resetTables truncates every table', async () => {
    await createUserRecord(t.prisma);
    await resetTables(t.prisma);
    expect(await t.prisma.user.count()).toBe(0);
    expect(await t.prisma.auditEvent.count()).toBe(0);
  });

  it('shared enums mirror the Prisma enums', () => {
    const same = (prismaEnum: Record<string, string>, options: readonly string[]) =>
      expect(Object.values(prismaEnum).sort()).toEqual([...options].sort());
    same($Enums.Role, RoleSchema.options);
    same($Enums.DropStatus, DropStatusSchema.options);
    same($Enums.ReportReason, ReportReasonSchema.options);
    same($Enums.ReportStatus, ReportStatusSchema.options);
    same($Enums.AuditAction, AuditActionSchema.options);
  });
});
