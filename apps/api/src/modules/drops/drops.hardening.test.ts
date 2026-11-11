/**
 * Review fixes C-12 (audit failure after a committed change must not fail the request), C-26 (reports for
 * gone drops answer 410) and C-27 (concurrent owner deletes write one DROP_DELETED).
 */
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import {
  complete,
  createReadyDrop,
  createDropOk,
  createBody,
  fakeWrappedKey,
  openDrop,
  passwordFixture,
  testFile,
} from './test-utils';
import { authHeader, createUserRecord } from '../../../test/factories';
import { purgeDropBlobs } from './lifecycle';
import { uploadAll } from './test-utils';

describe('drops hardening', () => {
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp();
    await resetTables(t.prisma);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });
  afterAll(async () => {
    await t.close();
  });

  const failAudit = () =>
    vi.spyOn(t.ctx.audit, 'record').mockRejectedValue(new Error('audit insert failed'));

  describe('C-12: audit is best-effort after the state change committed', () => {
    it('open still returns the token when the audit insert fails (burn-after-read is not burned)', async () => {
      const d = await createReadyDrop(t.app, { body: { maxDownloads: 1 } });
      failAudit();
      const res = await openDrop(t.app, d.dropId);
      expect(res.status).toBe(200);
      expect(typeof res.body.downloadToken).toBe('string');
      expect(res.body.downloadsRemaining).toBe(0);
    });

    it('complete and delete still succeed when the audit insert fails', async () => {
      const files = [testFile(500)];
      const drop = await createDropOk(t.app, createBody(files));
      await uploadAll(t.app, drop, files);
      failAudit();
      expect((await complete(t.app, drop)).status).toBe(200);
      const del = await request(t.app)
        .delete(`/api/drops/${drop.dropId}`)
        .set('x-owner-token', drop.ownerToken);
      expect(del.status).toBe(204);
    });
  });

  describe('C-26: reports for gone drops', () => {
    it('answers 410 with the reason for a deleted drop and stores nothing', async () => {
      const d = await createReadyDrop(t.app);
      await request(t.app).delete(`/api/drops/${d.dropId}`).set('x-owner-token', d.ownerToken);
      const res = await request(t.app)
        .post(`/api/drops/${d.dropId}/report`)
        .send({ reason: 'OTHER' });
      expect(res.status).toBe(410);
      expect(res.body.error.details).toEqual({ reason: 'DELETED' });
      expect(await t.prisma.report.count({ where: { dropId: d.dropId } })).toBe(0);
    });
  });

  describe('C-13: a purged drop keeps no password verifier, and a deleted one no manifest', () => {
    const pwDrop = async (headers: Record<string, string> = {}) =>
      createReadyDrop(t.app, {
        body: {
          password: passwordFixture().password,
          ...(headers.Authorization ? { ownerWrappedKey: fakeWrappedKey() } : {}),
        },
        headers,
      });

    it('owner delete: verifier, wrapped keys, manifest and chunk rows are wiped; 410 DELETED stays', async () => {
      const user = await createUserRecord(t.prisma);
      const d = await pwDrop({ Authorization: authHeader(user) });
      expect(await t.prisma.dropChunk.count({ where: { dropId: d.dropId } })).toBeGreaterThan(0);
      await request(t.app)
        .delete(`/api/drops/${d.dropId}`)
        .set('x-owner-token', d.ownerToken)
        .expect(204);
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: d.dropId } });
      expect(row).toMatchObject({
        status: 'DELETED',
        encryptedManifest: '',
        ownerWrappedKey: null,
        wrappedDropKey: null,
        authKeyHash: null,
        pwKdfSalt: null,
        pwKdfMemoryKiB: null,
        pwKdfIterations: null,
        pwKdfParallelism: null,
      });
      expect(row.expiresAt).toBeInstanceOf(Date);
      expect(await t.prisma.dropChunk.count({ where: { dropId: d.dropId } })).toBe(0);
      const meta = await request(t.app).get(`/api/drops/${d.dropId}`);
      expect(meta.status).toBe(410);
      expect(meta.body.error.details.reason).toBe('DELETED');
    });

    it('an expired owned drop loses only the password verifier (the owner history still decrypts)', async () => {
      const user = await createUserRecord(t.prisma);
      const d = await pwDrop({ Authorization: authHeader(user) });
      await t.prisma.drop.update({ where: { id: d.dropId }, data: { status: 'EXPIRED' } });
      await purgeDropBlobs(t.ctx, d.dropId, new Date());
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: d.dropId } });
      expect(row.wrappedDropKey).toBeNull();
      expect(row.authKeyHash).toBeNull();
      expect(row.encryptedManifest).not.toBe('');
      expect(row.ownerWrappedKey).not.toBeNull();
    });

    it('a purged anonymous drop keeps no manifest either', async () => {
      const d = await pwDrop();
      await t.prisma.drop.update({ where: { id: d.dropId }, data: { status: 'EXPIRED' } });
      await purgeDropBlobs(t.ctx, d.dropId, new Date());
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: d.dropId } });
      expect(row.encryptedManifest).toBe('');
      expect(row.wrappedDropKey).toBeNull();
    });
  });

  describe('C-27: concurrent owner deletes', () => {
    it('write exactly one DROP_DELETED event', async () => {
      const owner = await t.prisma.user.create({
        data: {
          email: `c27-${Date.now()}@test.local`,
          authKeyHash: 'x',
          kdfSalt: 'x',
          kdfMemoryKiB: 19456,
          kdfIterations: 2,
          kdfParallelism: 1,
          wrappedAccountKey: 'x',
          wrappedAccountKeyRecovery: 'x',
          recoveryAuthHash: 'x',
          storageQuotaBytes: 1_000_000_000n,
        },
      });
      const d = await createReadyDrop(t.app);
      await t.prisma.drop.update({ where: { id: d.dropId }, data: { ownerId: owner.id } });
      const results = await Promise.all(
        Array.from({ length: 5 }, () =>
          request(t.app).delete(`/api/drops/${d.dropId}`).set('x-owner-token', d.ownerToken),
        ),
      );
      expect(results.map((r) => r.status)).toEqual([204, 204, 204, 204, 204]);
      expect(
        await t.prisma.auditEvent.count({ where: { dropId: d.dropId, action: 'DROP_DELETED' } }),
      ).toBe(1);
    });
  });
});
