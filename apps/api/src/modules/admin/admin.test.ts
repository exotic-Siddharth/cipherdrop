/**
 * /api/admin (spec section 10 "Admin", R13): stats, reports, resolve, review grant, users, RBAC.
 */
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createAdminRecord, createUserRecord } from '../../../test/factories';
import { isAppError } from '../../lib/errors';
import {
  createBody,
  createDropOk,
  createReadyDrop,
  fakeWrappedKey,
  getChunk,
  HOUR,
  testClock,
  testFile,
  token32,
} from '../drops/test-utils';

const T0 = new Date('2026-11-08T15:30:00.000Z');
const DAY = 24 * HOUR;

describe('admin API', () => {
  let t: TestApp;
  const clock = testClock(T0);

  beforeAll(async () => {
    t = await createTestApp({ now: clock.now });
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
    clock.set(T0);
  });

  const as = (user: { id: string; role: 'USER' | 'ADMIN' }) => ({
    Authorization: authHeader(user),
  });

  async function report(dropId: string, body: Record<string, unknown> = { reason: 'MALWARE' }) {
    const res = await request(t.app).post(`/api/drops/${dropId}/report`).send(body);
    expect(res.status).toBe(201);
    return res.body.id as string;
  }

  async function blobExists(dropId: string, fileId: string): Promise<boolean> {
    try {
      (await t.storage.getChunkStream(dropId, fileId, 0)).destroy();
      return true;
    } catch (err) {
      if (isAppError(err) && err.code === 'NOT_FOUND') return false;
      throw err;
    }
  }

  describe('RBAC', () => {
    const routes: [
      method: 'get' | 'post' | 'patch',
      path: (ids: { drop: string; report: string; user: string }) => string,
      body?: object,
    ][] = [
      ['get', () => '/api/admin/stats'],
      ['get', () => '/api/admin/reports'],
      ['post', (i) => `/api/admin/reports/${i.report}/resolve`, { action: 'DISMISS' }],
      ['post', (i) => `/api/admin/drops/${i.drop}/grant`],
      ['get', () => '/api/admin/users'],
      ['patch', (i) => `/api/admin/users/${i.user}`, { storageQuotaBytes: 1 }],
    ];

    it('answers 401 without a token and 403 for regular users on every admin route', async () => {
      const user = await createUserRecord(t.prisma);
      const drop = await createReadyDrop(t.app);
      const ids = { drop: drop.dropId, report: await report(drop.dropId), user: user.id };
      for (const [method, path, body] of routes) {
        const anon = await request(t.app)[method](path(ids)).send(body);
        expect(anon.status, `${method} ${path(ids)}`).toBe(401);
        const res = await request(t.app)[method](path(ids)).set(as(user)).send(body);
        expect(res.status, `${method} ${path(ids)}`).toBe(403);
        expect(res.body.error.code).toBe('FORBIDDEN');
      }
      // Nothing changed.
      expect((await t.prisma.report.findUniqueOrThrow({ where: { id: ids.report } })).status).toBe(
        'OPEN',
      );
      expect(await t.prisma.downloadGrant.count()).toBe(0);
    });

    it('re-checks the role in the database (a demoted admin is refused)', async () => {
      const admin = await createAdminRecord(t.prisma);
      const header = as(admin);
      expect((await request(t.app).get('/api/admin/stats').set(header)).status).toBe(200);
      await t.prisma.user.update({ where: { id: admin.id }, data: { role: 'USER' } });
      expect((await request(t.app).get('/api/admin/stats').set(header)).status).toBe(403);
    });
  });

  describe('GET /admin/stats', () => {
    it('returns totals and 14 daily upload buckets, oldest first, ending today (UTC)', async () => {
      const admin = await createAdminRecord(t.prisma);
      const owner = await createUserRecord(t.prisma);
      const a = await createReadyDrop(t.app, { files: [testFile(1000)] });
      const b = await createReadyDrop(t.app, {
        files: [testFile(500)],
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: as(owner),
      });
      const uploading = await createDropOk(t.app, createBody([testFile(10)]));
      const old = await createReadyDrop(t.app, { files: [testFile(10)] });
      const ancient = await createReadyDrop(t.app, { files: [testFile(10)] });
      await t.prisma.drop.update({
        where: { id: old.dropId },
        data: { createdAt: new Date(T0.getTime() - 13 * DAY) },
      });
      await t.prisma.drop.update({
        where: { id: ancient.dropId },
        data: {
          createdAt: new Date(T0.getTime() - 14 * DAY),
          status: 'EXPIRED',
          blobsDeletedAt: T0,
        },
      });
      await report(a.dropId);
      const resolvedId = await report(b.dropId);
      await t.prisma.report.update({ where: { id: resolvedId }, data: { status: 'DISMISSED' } });

      const res = await request(t.app).get('/api/admin/stats').set(as(admin));
      expect(res.status).toBe(200);
      const ct = (n: number) => n + 16;
      expect(res.body).toMatchObject({
        users: 2,
        activeDrops: 4, // a, b, old (READY) + uploading
        totalDrops: 5,
        storageBytes: ct(1000) + ct(500) + ct(10),
        openReports: 1,
      });
      const days = res.body.uploadsLast14d as { date: string; drops: number; bytes: number }[];
      expect(days).toHaveLength(14);
      expect(days[0]!.date).toBe('2026-10-26');
      expect(days[13]!.date).toBe('2026-11-08');
      expect(days[13]).toEqual({
        date: '2026-11-08',
        drops: 3,
        bytes: ct(1000) + ct(500) + ct(10),
      });
      expect(days[0]).toEqual({ date: '2026-10-26', drops: 1, bytes: ct(10) });
      expect(days.slice(1, 13).every((d) => d.drops === 0 && d.bytes === 0)).toBe(true);
      void uploading;
    });
  });

  describe('reports', () => {
    it('lists reports with the decryption key (admins only), newest first, filtered by status', async () => {
      const admin = await createAdminRecord(t.prisma);
      const owner = await createUserRecord(t.prisma);
      const drop = await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: as(owner),
      });
      const key = token32();
      const first = await report(drop.dropId, { reason: 'PHISHING', details: 'looks like a bank' });
      clock.advance(1000);
      const second = await report(drop.dropId, { reason: 'MALWARE', decryptionKey: key });
      await t.prisma.report.update({
        where: { id: first },
        data: { createdAt: new Date(T0.getTime() - 1000) },
      });

      const res = await request(t.app).get('/api/admin/reports').set(as(admin));
      expect(res.status).toBe(200);
      expect(res.body.total).toBe(2);
      expect(res.body.page).toBe(1);
      expect(res.body.items.map((r: { id: string }) => r.id)).toEqual([second, first]);
      expect(res.body.items[0]).toMatchObject({
        id: second,
        reason: 'MALWARE',
        details: null,
        status: 'OPEN',
        hasKey: true,
        decryptionKey: key,
        drop: {
          id: drop.dropId,
          status: 'READY',
          fileCount: 1,
          totalBytes: drop.files[0]!.ciphertextBytes,
          ownerEmail: owner.email,
        },
      });
      expect(res.body.items[1]).toMatchObject({
        hasKey: false,
        decryptionKey: null,
        details: 'looks like a bank',
      });

      await t.prisma.report.update({ where: { id: first }, data: { status: 'DISMISSED' } });
      const open = await request(t.app).get('/api/admin/reports?status=OPEN').set(as(admin));
      expect(open.body.items.map((r: { id: string }) => r.id)).toEqual([second]);
      const paged = await request(t.app).get('/api/admin/reports?page=2&pageSize=1').set(as(admin));
      expect(paged.body).toMatchObject({ total: 2, page: 2, pageSize: 1 });
      expect(paged.body.items).toHaveLength(1);

      // The key never leaves through recipient endpoints.
      const meta = await request(t.app).get(`/api/drops/${drop.dropId}`);
      expect(JSON.stringify(meta.body)).not.toContain(key);
    });

    it('DISABLE_DROP disables the drop, deletes its blobs, resolves its reports and answers 410 to recipients', async () => {
      const admin = await createAdminRecord(t.prisma);
      const owner = await createUserRecord(t.prisma);
      const drop = await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: as(owner),
      });
      const tok = (await request(t.app).post(`/api/drops/${drop.dropId}/open`).send({})).body
        .downloadToken as string;
      const r1 = await report(drop.dropId);
      const r2 = await report(drop.dropId, { reason: 'ILLEGAL' });

      const res = await request(t.app)
        .post(`/api/admin/reports/${r1}/resolve`)
        .set(as(admin))
        .send({ action: 'DISABLE_DROP' });
      expect(res.status).toBe(204);

      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.status).toBe('DISABLED');
      expect(row.blobsDeletedAt).toBeInstanceOf(Date);
      expect(await blobExists(drop.dropId, drop.files[0]!.id)).toBe(false);
      for (const id of [r1, r2]) {
        const rep = await t.prisma.report.findUniqueOrThrow({ where: { id } });
        expect(rep.status).toBe('RESOLVED');
        expect(rep.resolvedById).toBe(admin.id);
        expect(rep.resolvedAt?.toISOString()).toBe(T0.toISOString());
      }
      expect(
        Number(
          (await t.prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).storageUsedBytes,
        ),
      ).toBe(0);
      expect(
        await t.prisma.auditEvent.count({ where: { userId: owner.id, action: 'DROP_DISABLED' } }),
      ).toBe(1);

      const meta = await request(t.app).get(`/api/drops/${drop.dropId}`);
      expect(meta.status).toBe(410);
      expect(meta.body.error.details.reason).toBe('DISABLED');
      expect((await getChunk(t.app, drop.dropId, tok, drop.files[0]!.id, 0)).status).toBe(410);

      // Resolving again is a conflict.
      const again = await request(t.app)
        .post(`/api/admin/reports/${r1}/resolve`)
        .set(as(admin))
        .send({ action: 'DISMISS' });
      expect(again.status).toBe(409);
    });

    it('DISMISS closes the report and leaves the drop alone', async () => {
      const admin = await createAdminRecord(t.prisma);
      const drop = await createReadyDrop(t.app);
      const id = await report(drop.dropId);
      const res = await request(t.app)
        .post(`/api/admin/reports/${id}/resolve`)
        .set(as(admin))
        .send({ action: 'DISMISS' });
      expect(res.status).toBe(204);
      const rep = await t.prisma.report.findUniqueOrThrow({ where: { id } });
      expect(rep.status).toBe('DISMISSED');
      expect(rep.resolvedById).toBe(admin.id);
      expect((await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } })).status).toBe(
        'READY',
      );
      expect(await blobExists(drop.dropId, drop.files[0]!.id)).toBe(true);
    });

    it('validates the action and answers 404 for an unknown report', async () => {
      const admin = await createAdminRecord(t.prisma);
      expect(
        (
          await request(t.app)
            .post('/api/admin/reports/nope/resolve')
            .set(as(admin))
            .send({ action: 'DISMISS' })
        ).status,
      ).toBe(404);
      const drop = await createReadyDrop(t.app);
      const id = await report(drop.dropId);
      expect(
        (
          await request(t.app)
            .post(`/api/admin/reports/${id}/resolve`)
            .set(as(admin))
            .send({ action: 'BAN' })
        ).status,
      ).toBe(400);
    });
  });

  describe('POST /admin/drops/:id/grant', () => {
    it('issues a non-consuming, audited review grant that can download chunks', async () => {
      const admin = await createAdminRecord(t.prisma);
      const drop = await createReadyDrop(t.app, { body: { maxDownloads: 1 } });
      const row0 = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      const res = await request(t.app)
        .post(`/api/admin/drops/${drop.dropId}/grant`)
        .set(as(admin))
        .set('X-Forwarded-For', '198.51.100.4')
        .send();
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        downloadToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        expiresAt: new Date(T0.getTime() + 30 * 60_000).toISOString(),
        encryptedManifest: row0.encryptedManifest,
      });
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.downloadCount).toBe(0);
      expect(row.status).toBe('READY');
      const grant = await t.prisma.downloadGrant.findFirstOrThrow({
        where: { dropId: drop.dropId },
      });
      expect(grant.isAdmin).toBe(true);
      const ev = await t.prisma.auditEvent.findFirstOrThrow({
        where: { userId: admin.id, dropId: drop.dropId },
      });
      expect(ev.action).toBe('ADMIN_REVIEW_GRANT');
      expect(ev.metadata).toMatchObject({ adminReview: true });
      expect(ev.ipPrefix).toBe('198.51.100.0/24');

      const chunk = await getChunk(
        t.app,
        drop.dropId,
        res.body.downloadToken,
        drop.files[0]!.id,
        0,
      );
      expect(chunk.status).toBe(200);
      expect((chunk.body as Buffer).equals(drop.chunks.get(drop.files[0]!.id)![0]!)).toBe(true);
      // The single public download is still available.
      expect((await request(t.app).post(`/api/drops/${drop.dropId}/open`).send({})).status).toBe(
        200,
      );
    });

    it('works for an EXHAUSTED drop whose blobs are kept, refuses gone and unknown drops', async () => {
      const admin = await createAdminRecord(t.prisma);
      const exhausted = await createReadyDrop(t.app, { body: { maxDownloads: 1 } });
      await request(t.app).post(`/api/drops/${exhausted.dropId}/open`).send({});
      expect(
        (await request(t.app).post(`/api/admin/drops/${exhausted.dropId}/grant`).set(as(admin)))
          .status,
      ).toBe(200);

      const disabled = await createReadyDrop(t.app);
      await t.prisma.drop.update({
        where: { id: disabled.dropId },
        data: { status: 'DISABLED', blobsDeletedAt: T0 },
      });
      const gone = await request(t.app)
        .post(`/api/admin/drops/${disabled.dropId}/grant`)
        .set(as(admin));
      expect(gone.status).toBe(410);
      expect(gone.body.error.details.reason).toBe('DISABLED');

      const uploading = await createDropOk(t.app, createBody([testFile(3)]));
      expect(
        (await request(t.app).post(`/api/admin/drops/${uploading.dropId}/grant`).set(as(admin)))
          .status,
      ).toBe(404);
      expect(
        (await request(t.app).post('/api/admin/drops/AAAAAAAAAAAAAAAAAAAAAA/grant').set(as(admin)))
          .status,
      ).toBe(404);
    });
  });

  describe('users', () => {
    it('lists users with search, drop counts and MFA state', async () => {
      const admin = await createAdminRecord(t.prisma, { email: 'root-admin@test.local' });
      const alice = await createUserRecord(t.prisma, {
        email: 'alice.wonder@test.local',
        totpEnabledAt: T0,
        storageUsedBytes: BigInt(1234),
      });
      await createUserRecord(t.prisma, { email: 'bob@test.local' });
      await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: as(alice),
      });

      const all = await request(t.app).get('/api/admin/users').set(as(admin));
      expect(all.status).toBe(200);
      expect(all.body.total).toBe(3);

      const res = await request(t.app).get('/api/admin/users?search=ALICE').set(as(admin));
      expect(res.status).toBe(200);
      expect(res.body.total).toBe(1);
      expect(res.body.items[0]).toEqual({
        id: alice.id,
        email: 'alice.wonder@test.local',
        role: 'USER',
        totpEnabled: true,
        storageQuotaBytes: 5 * 1024 * 1024 * 1024,
        storageUsedBytes: 1234 + 1016,
        dropCount: 1,
        lockedUntil: null,
        createdAt: alice.createdAt.toISOString(),
      });
      expect(JSON.stringify(res.body)).not.toMatch(
        /authKeyHash|wrappedAccountKey|totpSecret|recoveryAuthHash/,
      );
    });

    it('edits the quota and the role', async () => {
      const admin = await createAdminRecord(t.prisma);
      const user = await createUserRecord(t.prisma);
      const res = await request(t.app)
        .patch(`/api/admin/users/${user.id}`)
        .set(as(admin))
        .send({ storageQuotaBytes: 1000, role: 'ADMIN' });
      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({ id: user.id, role: 'ADMIN', storageQuotaBytes: 1000 });
      // The promotion is stored; admin routes need a token carrying the new role (issued on the next refresh).
      expect((await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } })).role).toBe(
        'ADMIN',
      );
      expect(
        (
          await request(t.app)
            .get('/api/admin/stats')
            .set(as({ id: user.id, role: 'ADMIN' }))
        ).status,
      ).toBe(200);
      // And the quota is enforced on create.
      const over = await request(t.app)
        .post('/api/drops')
        .set(as(user))
        .send(createBody([testFile(2000)], { ownerWrappedKey: fakeWrappedKey() }));
      expect(over.status).toBe(413);
      expect(over.body.error.code).toBe('QUOTA_EXCEEDED');
    });

    it('validates the patch, answers 404 for unknown users and refuses self-demotion', async () => {
      const admin = await createAdminRecord(t.prisma);
      const user = await createUserRecord(t.prisma);
      expect(
        (await request(t.app).patch(`/api/admin/users/${user.id}`).set(as(admin)).send({})).status,
      ).toBe(400);
      expect(
        (
          await request(t.app)
            .patch(`/api/admin/users/${user.id}`)
            .set(as(admin))
            .send({ storageQuotaBytes: -1 })
        ).status,
      ).toBe(400);
      expect(
        (
          await request(t.app)
            .patch('/api/admin/users/unknownid')
            .set(as(admin))
            .send({ role: 'USER' })
        ).status,
      ).toBe(404);
      const self = await request(t.app)
        .patch(`/api/admin/users/${admin.id}`)
        .set(as(admin))
        .send({ role: 'USER' });
      expect(self.status).toBe(400);
      expect((await t.prisma.user.findUniqueOrThrow({ where: { id: admin.id } })).role).toBe(
        'ADMIN',
      );
    });
  });
});
