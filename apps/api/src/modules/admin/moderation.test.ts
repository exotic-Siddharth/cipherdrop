/**
 * Moderation: the admin audit trail (server-4), suspension and takedown by id (server-6).
 */
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createAdminRecord, createUserRecord } from '../../../test/factories';
import { bearer, loginViaApi, newSession, registerViaApi } from '../auth/testkit';
import { chunkBlobFiles, createReadyDrop, testClock } from '../drops/test-utils';

const T0 = new Date('2026-11-22T10:00:00.000Z');

describe('moderation', () => {
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

  async function report(dropId: string) {
    const res = await request(t.app)
      .post(`/api/drops/${dropId}/report`)
      .send({ reason: 'MALWARE' });
    expect(res.status).toBe(201);
    return res.body.id as string;
  }

  describe('admin actions are audited with the acting admin (server-4)', () => {
    it('records role and quota edits, dismissals and disables, and lists them in GET /admin/audit', async () => {
      const admin = await createAdminRecord(t.prisma);
      const user = await createUserRecord(t.prisma, { storageQuotaBytes: 1000n });
      const patch = await request(t.app)
        .patch(`/api/admin/users/${user.id}`)
        .set(as(admin))
        .set('X-Forwarded-For', '198.51.100.7')
        .send({ storageQuotaBytes: 5000 });
      expect(patch.status).toBe(200);
      const updated = await t.prisma.auditEvent.findFirstOrThrow({
        where: { action: 'ADMIN_USER_UPDATED' },
      });
      expect(updated).toMatchObject({
        actorId: admin.id,
        userId: null,
        ipPrefix: '198.51.100.0/24',
        metadata: { targetUserId: user.id, storageQuotaBytes: { from: 1000, to: 5000 } },
      });

      const dismissed = await createReadyDrop(t.app);
      const r1 = await report(dismissed.dropId);
      expect(
        (
          await request(t.app)
            .post(`/api/admin/reports/${r1}/resolve`)
            .set(as(admin))
            .send({ action: 'DISMISS' })
        ).status,
      ).toBe(204);
      const disabled = await createReadyDrop(t.app);
      const r2 = await report(disabled.dropId);
      expect(
        (
          await request(t.app)
            .post(`/api/admin/reports/${r2}/resolve`)
            .set(as(admin))
            .send({ action: 'DISABLE_DROP' })
        ).status,
      ).toBe(204);

      const res = await request(t.app).get('/api/admin/audit').set(as(admin));
      expect(res.status).toBe(200);
      expect(res.body.total).toBe(3);
      expect(res.body.items.map((e: { action: string }) => e.action).sort()).toEqual([
        'ADMIN_DROP_DISABLED',
        'ADMIN_REPORT_DISMISSED',
        'ADMIN_USER_UPDATED',
      ]);
      const ev = res.body.items.find((e: { action: string }) => e.action === 'ADMIN_USER_UPDATED');
      expect(ev).toMatchObject({
        actor: { id: admin.id, email: admin.email },
        byOperator: false,
        subject: { id: user.id, email: user.email },
      });
      const dis = res.body.items.find(
        (e: { action: string }) => e.action === 'ADMIN_DROP_DISABLED',
      );
      expect(dis).toMatchObject({ dropId: disabled.dropId, metadata: { reportId: r2 } });

      // Filters: by target account, by action; scope=all also lists the users' own events.
      const byUser = await request(t.app).get(`/api/admin/audit?userId=${user.id}`).set(as(admin));
      expect(byUser.body.items.map((e: { action: string }) => e.action)).toEqual([
        'ADMIN_USER_UPDATED',
      ]);
      const byAction = await request(t.app)
        .get('/api/admin/audit?action=ADMIN_REPORT_DISMISSED')
        .set(as(admin));
      expect(byAction.body.total).toBe(1);
      const all = await request(t.app).get('/api/admin/audit?scope=all').set(as(admin));
      expect(all.body.items.some((e: { action: string }) => e.action === 'DROP_DISABLED')).toBe(
        true,
      );
      expect((await request(t.app).get('/api/admin/audit?scope=x').set(as(admin))).status).toBe(
        400,
      );
    });

    it('keeps the record when the target or the acting admin deletes their account', async () => {
      const admin = await createAdminRecord(t.prisma);
      const user = await createUserRecord(t.prisma);
      await request(t.app)
        .patch(`/api/admin/users/${user.id}`)
        .set(as(admin))
        .send({ storageQuotaBytes: 1 });
      await t.prisma.user.delete({ where: { id: user.id } });
      await t.prisma.user.delete({ where: { id: admin.id } });
      const ev = await t.prisma.auditEvent.findFirstOrThrow({
        where: { action: 'ADMIN_USER_UPDATED' },
      });
      expect(ev.actorId).toBeNull();
      expect(ev.metadata).toMatchObject({ targetUserId: user.id });
    });

    it('is admin only', async () => {
      const user = await createUserRecord(t.prisma);
      expect((await request(t.app).get('/api/admin/audit')).status).toBe(401);
      expect((await request(t.app).get('/api/admin/audit').set(as(user))).status).toBe(403);
    });
  });

  describe('suspension (server-6)', () => {
    it('signs the account out everywhere, refuses login only after a correct proof, and refresh', async () => {
      const admin = await createAdminRecord(t.prisma);
      const u = await registerViaApi(t.app);
      const s = await newSession(t.app, u);

      const res = await request(t.app)
        .patch(`/api/admin/users/${u.user.id}`)
        .set(as(admin))
        .send({ suspended: true, suspendedReason: 'Repeat malware uploads' });
      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({
        suspendedAt: T0.toISOString(),
        suspendedReason: 'Repeat malware uploads',
      });

      // The live access token and the refresh cookie are dead.
      expect(
        (await request(t.app).get('/api/me').set('Authorization', bearer(s.accessToken))).status,
      ).toBe(401);
      expect((await request(t.app).post('/api/auth/refresh').set('Cookie', s.cookie)).status).toBe(
        401,
      );
      // A wrong password still gets the generic 401; the right one learns about the suspension.
      expect((await loginViaApi(t.app, u.email, 'wrong password')).status).toBe(401);
      const login = await loginViaApi(t.app, u.email, u.password);
      expect(login.status).toBe(403);
      expect(login.body.error.details).toEqual({ reason: 'ACCOUNT_SUSPENDED' });

      const ev = await t.prisma.auditEvent.findFirstOrThrow({
        where: { action: 'ADMIN_USER_SUSPENDED' },
      });
      expect(ev).toMatchObject({
        actorId: admin.id,
        metadata: { targetUserId: u.user.id, reason: 'Repeat malware uploads', revokedSessions: 2 },
      });

      const lift = await request(t.app)
        .patch(`/api/admin/users/${u.user.id}`)
        .set(as(admin))
        .send({ suspended: false });
      expect(lift.body.user.suspendedAt).toBeNull();
      expect((await loginViaApi(t.app, u.email, u.password)).status).toBe(200);
      expect(await t.prisma.auditEvent.count({ where: { action: 'ADMIN_USER_UNSUSPENDED' } })).toBe(
        1,
      );
    });

    it('needs a reason, and refuses admins (demote first), self-suspension and promoting a suspended account', async () => {
      const admin = await createAdminRecord(t.prisma);
      const other = await createAdminRecord(t.prisma);
      const user = await createUserRecord(t.prisma, { totpEnabledAt: T0 });
      const patch = (id: string, body: object) =>
        request(t.app).patch(`/api/admin/users/${id}`).set(as(admin)).send(body);
      expect((await patch(user.id, { suspended: true })).status).toBe(400);
      expect((await patch(admin.id, { suspended: true, suspendedReason: 'x' })).status).toBe(400);
      expect((await patch(other.id, { suspended: true, suspendedReason: 'x' })).status).toBe(409);
      expect((await patch(user.id, { suspended: true, suspendedReason: 'x' })).status).toBe(200);
      expect((await patch(user.id, { role: 'ADMIN' })).status).toBe(409);
      expect((await t.prisma.user.findUniqueOrThrow({ where: { id: other.id } })).suspendedAt).toBe(
        null,
      );
    });
  });

  describe('POST /admin/drops/:id/disable (server-6)', () => {
    it('takes a drop down without a report, resolves its open reports and audits the reason', async () => {
      const admin = await createAdminRecord(t.prisma);
      const drop = await createReadyDrop(t.app);
      const reportId = await report(drop.dropId);
      const res = await request(t.app)
        .post(`/api/admin/drops/${drop.dropId}/disable`)
        .set(as(admin))
        .send({ reason: 'Takedown notice 2026-11-22' });
      expect(res.status).toBe(204);
      expect((await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } })).status).toBe(
        'DISABLED',
      );
      expect((await chunkBlobFiles(t.storageDir, drop.dropId, drop.files[0]!.id, 0)).length).toBe(
        0,
      );
      expect((await t.prisma.report.findUniqueOrThrow({ where: { id: reportId } })).status).toBe(
        'RESOLVED',
      );
      expect(
        await t.prisma.auditEvent.findFirstOrThrow({ where: { action: 'ADMIN_DROP_DISABLED' } }),
      ).toMatchObject({
        actorId: admin.id,
        dropId: drop.dropId,
        metadata: { reason: 'Takedown notice 2026-11-22', reportsResolved: 1 },
      });
      expect((await request(t.app).get(`/api/drops/${drop.dropId}`)).status).toBe(410);

      const again = await request(t.app)
        .post(`/api/admin/drops/${drop.dropId}/disable`)
        .set(as(admin))
        .send({ reason: 'again' });
      expect(again.status).toBe(409);
      expect(
        (
          await request(t.app)
            .post('/api/admin/drops/AAAAAAAAAAAAAAAAAAAAAA/disable')
            .set(as(admin))
            .send({ reason: 'x' })
        ).status,
      ).toBe(404);
      expect(
        (
          await request(t.app)
            .post(`/api/admin/drops/${drop.dropId}/disable`)
            .set(as(admin))
            .send({})
        ).status,
      ).toBe(400);
    });
  });
});
