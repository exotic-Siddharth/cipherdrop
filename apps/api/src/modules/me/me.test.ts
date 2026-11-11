import { randomBytes } from 'node:crypto';
import {
  AuditEventPageSchema,
  MeResponseSchema,
  OwnerDropPageSchema,
  type DropStatus,
} from '@cipherdrop/shared';
import type { Prisma } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { authHeader, createUserRecord } from '../../../test/factories';
import { isSidDenylisted } from '../../lib/redis';
import type { StorageDriver } from '../../storage';
import {
  bearer,
  enableTotpViaApi,
  newSession,
  registerViaApi,
  sidOf,
  totpCode,
} from '../auth/testkit';

/** Lane B2 implements the drivers in parallel: DELETE /me must only go through storage.deleteDrop. */
const deleteDrop = vi.fn<StorageDriver['deleteDrop']>(async () => {});
const storage: StorageDriver = {
  init: async () => {},
  putChunk: async () => {},
  getChunkStream: () => Promise.reject(new Error('not used')),
  deleteDrop,
  healthCheck: async () => {},
};

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp({ storage });
});

afterAll(async () => {
  await t.close();
});

const b64 = (n: number) => randomBytes(n).toString('base64url');

let created = 0;
async function createDrop(
  ownerId: string | null,
  status: DropStatus,
  overrides: Partial<Prisma.DropUncheckedCreateInput> = {},
) {
  created += 1;
  return t.prisma.drop.create({
    data: {
      id: b64(16),
      ownerId,
      ownerTokenHash: b64(32),
      uploadTokenHash: b64(32),
      status,
      encryptedManifest: b64(80),
      ownerWrappedKey: b64(60),
      totalCiphertextBytes: BigInt(1000 + created),
      fileCount: 2,
      maxDownloads: 5,
      downloadCount: 2,
      expiresAt: new Date(Date.now() + 86_400_000),
      createdAt: new Date(Date.UTC(2026, 10, 1) + created * 60_000),
      ...overrides,
    },
  });
}

describe('GET /me and PATCH /me/settings', () => {
  it('returns the user with storage numbers; 401 without a token', async () => {
    const user = await createUserRecord(t.prisma, {
      storageQuotaBytes: BigInt(5 * 1024 ** 3),
      storageUsedBytes: BigInt(123_456_789),
    });
    const res = await request(t.app).get('/api/me').set('Authorization', authHeader(user));
    expect(res.status).toBe(200);
    const { user: me } = MeResponseSchema.parse(res.body);
    expect(me).toEqual({
      id: user.id,
      email: user.email,
      role: 'USER',
      totpEnabled: false,
      autoLockMinutes: 15,
      storageQuotaBytes: 5 * 1024 ** 3,
      storageUsedBytes: 123_456_789,
      createdAt: user.createdAt.toISOString(),
    });
    expect((await request(t.app).get('/api/me')).status).toBe(401);
  });

  it('PATCH /me/settings accepts 5/15/60 and rejects anything else', async () => {
    const user = await createUserRecord(t.prisma);
    const patch = (autoLockMinutes: unknown) =>
      request(t.app)
        .patch('/api/me/settings')
        .set('Authorization', authHeader(user))
        .send({ autoLockMinutes });
    const ok = await patch(60);
    expect(ok.status).toBe(200);
    expect(MeResponseSchema.parse(ok.body).user.autoLockMinutes).toBe(60);
    for (const bad of [30, 0, '5', null]) {
      const res = await patch(bad);
      expect(res.status, String(bad)).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    }
    const row = await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row.autoLockMinutes).toBe(60);
  });
});

describe('GET /me/audit', () => {
  it('paginates newest first and filters by action', async () => {
    const user = await createUserRecord(t.prisma);
    const other = await createUserRecord(t.prisma);
    const base = Date.UTC(2026, 10, 2);
    const actions = [
      'REGISTER',
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
      'LOGIN_SUCCESS',
      'DROP_CREATED',
    ] as const;
    for (const [i, action] of actions.entries()) {
      await t.prisma.auditEvent.create({
        data: {
          userId: user.id,
          action,
          ipPrefix: '203.0.113.0/24',
          userAgent: 'Firefox on Linux',
          metadata: { n: i },
          createdAt: new Date(base + i * 1000),
          ...(action === 'DROP_CREATED' ? { dropId: 'AAAAAAAAAAAAAAAAAAAAAA' } : {}),
        },
      });
    }
    await t.prisma.auditEvent.create({ data: { userId: other.id, action: 'LOGIN_SUCCESS' } });
    const get = (query: string) =>
      request(t.app).get(`/api/me/audit${query}`).set('Authorization', authHeader(user));

    const page1 = await get('?page=1&pageSize=2');
    expect(page1.status).toBe(200);
    const p1 = AuditEventPageSchema.parse(page1.body);
    expect(p1.total).toBe(5);
    expect(p1.pageSize).toBe(2);
    expect(p1.items.map((e) => e.action)).toEqual(['DROP_CREATED', 'LOGIN_SUCCESS']);
    expect(p1.items[0]).toMatchObject({
      dropId: 'AAAAAAAAAAAAAAAAAAAAAA',
      ipPrefix: '203.0.113.0/24',
      userAgent: 'Firefox on Linux',
      metadata: { n: 4 },
    });
    expect(Object.keys(p1.items[0] ?? {}).sort()).toEqual(
      ['action', 'createdAt', 'dropId', 'id', 'ipPrefix', 'metadata', 'userAgent'].sort(),
    );
    const p3 = AuditEventPageSchema.parse((await get('?page=3&pageSize=2')).body);
    expect(p3.items.map((e) => e.action)).toEqual(['REGISTER']);

    const filtered = AuditEventPageSchema.parse((await get('?action=LOGIN_SUCCESS')).body);
    expect(filtered.total).toBe(2);
    expect(filtered.page).toBe(1);
    expect(filtered.pageSize).toBe(20);
    expect(filtered.items.every((e) => e.action === 'LOGIN_SUCCESS')).toBe(true);

    expect((await get('?action=NOPE')).status).toBe(400);
    expect((await get('?pageSize=101')).status).toBe(400);
  });

  it('shows the events the API records for the signed-in user', async () => {
    const u = await registerViaApi(t.app);
    await newSession(t.app, u, { 'X-Forwarded-For': '203.0.113.200' });
    const res = await request(t.app)
      .get('/api/me/audit')
      .set('Authorization', bearer(u.accessToken));
    const page = AuditEventPageSchema.parse(res.body);
    expect(page.items.map((e) => e.action)).toEqual(['LOGIN_SUCCESS', 'REGISTER']);
    expect(page.items.map((e) => e.ipPrefix)).toEqual(['203.0.113.0/24', '198.51.100.0/24']);
  });
});

describe('GET /me/drops (R6)', () => {
  it('filters active / expired / all (never DELETED), newest first, own drops only', async () => {
    const user = await createUserRecord(t.prisma);
    const stranger = await createUserRecord(t.prisma);
    const statuses: DropStatus[] = [
      'UPLOADING',
      'READY',
      'EXHAUSTED',
      'EXPIRED',
      'DELETED',
      'DISABLED',
      'READY',
    ];
    const drops: Awaited<ReturnType<typeof createDrop>>[] = [];
    for (const s of statuses) drops.push(await createDrop(user.id, s));
    await createDrop(stranger.id, 'READY');
    await createDrop(null, 'READY');
    const newestFirst = (list: typeof drops) => [...list].reverse().map((d) => d.id);
    const get = (query = '') =>
      request(t.app).get(`/api/me/drops${query}`).set('Authorization', authHeader(user));

    const active = OwnerDropPageSchema.parse((await get()).body);
    expect(active.items.map((d) => d.id)).toEqual(
      newestFirst(drops.filter((d) => d.status === 'UPLOADING' || d.status === 'READY')),
    );
    expect(active.total).toBe(3);

    const expired = OwnerDropPageSchema.parse((await get('?status=expired')).body);
    expect(expired.items.map((d) => d.id)).toEqual(
      newestFirst(drops.filter((d) => ['EXPIRED', 'EXHAUSTED', 'DISABLED'].includes(d.status))),
    );

    const all = OwnerDropPageSchema.parse((await get('?status=all')).body);
    expect(all.items.map((d) => d.id)).toEqual(
      newestFirst(drops.filter((d) => d.status !== 'DELETED')),
    );
    expect(all.total).toBe(6);

    const paged = OwnerDropPageSchema.parse((await get('?status=all&page=2&pageSize=4')).body);
    expect(paged.items).toHaveLength(2);
    expect(paged.total).toBe(6);
    expect((await get('?status=deleted')).status).toBe(400);
  });

  it('returns the OwnerDropSummary fields, including the encrypted manifest and owner wrap', async () => {
    const user = await createUserRecord(t.prisma);
    const opened = new Date(Date.UTC(2026, 10, 5, 8));
    const drop = await createDrop(user.id, 'READY', {
      maxDownloads: 3,
      downloadCount: 1,
      passwordProtected: true,
      lastOpenedAt: opened,
      ownerWrappedKey: null,
    });
    const res = await request(t.app).get('/api/me/drops').set('Authorization', authHeader(user));
    const [item] = OwnerDropPageSchema.parse(res.body).items;
    expect(item).toEqual({
      id: drop.id,
      status: 'READY',
      fileCount: 2,
      totalBytes: Number(drop.totalCiphertextBytes),
      maxDownloads: 3,
      downloadCount: 1,
      downloadsRemaining: 2,
      expiresAt: drop.expiresAt.toISOString(),
      createdAt: drop.createdAt.toISOString(),
      lastOpenedAt: opened.toISOString(),
      passwordProtected: true,
      encryptedManifest: drop.encryptedManifest,
      ownerWrappedKey: null,
    });
  });
});

describe('DELETE /me', () => {
  it('403 with a wrong authKey and nothing is deleted', async () => {
    const u = await registerViaApi(t.app);
    await createDrop(u.user.id, 'READY');
    deleteDrop.mockClear();
    const res = await request(t.app)
      .delete('/api/me')
      .set('Authorization', bearer(u.accessToken))
      .send({ authKey: Buffer.alloc(32, 1).toString('base64url') });
    expect(res.status).toBe(403);
    expect(deleteDrop).not.toHaveBeenCalled();
    expect(await t.prisma.user.count({ where: { id: u.user.id } })).toBe(1);
  });

  it('deletes the user, their drops and every owned blob; all sessions die at once', async () => {
    const u = await registerViaApi(t.app);
    const other = await newSession(t.app, u);
    const mine = [
      await createDrop(u.user.id, 'READY'),
      await createDrop(u.user.id, 'EXPIRED'),
      await createDrop(u.user.id, 'UPLOADING'),
    ];
    const strangers = await createDrop((await createUserRecord(t.prisma)).id, 'READY');
    deleteDrop.mockClear();

    const deletedEvents = () =>
      t.prisma.auditEvent.count({ where: { action: 'ACCOUNT_DELETED', userId: null } });
    const deletedBefore = await deletedEvents();

    const res = await request(t.app)
      .delete('/api/me')
      .set('Authorization', bearer(u.accessToken))
      .send({ authKey: u.authKey });
    expect(res.status).toBe(204);
    expect(deleteDrop.mock.calls.map((c) => c[0]).sort()).toEqual(mine.map((d) => d.id).sort());
    expect(await t.prisma.user.count({ where: { id: u.user.id } })).toBe(0);
    expect(await t.prisma.drop.count({ where: { id: { in: mine.map((d) => d.id) } } })).toBe(0);
    expect(await t.prisma.drop.count({ where: { id: strangers.id } })).toBe(1);
    expect(await t.prisma.session.count({ where: { userId: u.user.id } })).toBe(0);
    for (const sid of [sidOf(u.accessToken), other.sid]) {
      expect(await isSidDenylisted(t.redis, sid)).toBe(true);
    }
    expect(
      (await request(t.app).get('/api/me').set('Authorization', bearer(u.accessToken))).status,
    ).toBe(401);
    expect(
      (await request(t.app).post('/api/auth/refresh').set('Cookie', other.cookie)).status,
    ).toBe(401);
    expect(await deletedEvents()).toBe(deletedBefore + 1);
  });

  it('requires a TOTP code when TOTP is enabled', async () => {
    const u = await registerViaApi(t.app);
    const { secret } = await enableTotpViaApi(t.app, u.accessToken);
    const del = (body: object) =>
      request(t.app).delete('/api/me').set('Authorization', bearer(u.accessToken)).send(body);
    expect((await del({ authKey: u.authKey })).status).toBe(400);
    expect((await del({ authKey: u.authKey, code: totpCode(secret, 30_000) })).status).toBe(204);
    expect(await t.prisma.user.count({ where: { id: u.user.id } })).toBe(0);
  });

  it('a storage failure aborts the deletion (retryable) without deleting the user', async () => {
    const u = await registerViaApi(t.app);
    await createDrop(u.user.id, 'READY');
    deleteDrop.mockRejectedValueOnce(new Error('disk on fire'));
    const res = await request(t.app)
      .delete('/api/me')
      .set('Authorization', bearer(u.accessToken))
      .send({ authKey: u.authKey });
    expect(res.status).toBe(500);
    expect(res.body.error.message).not.toContain('disk');
    expect(await t.prisma.user.count({ where: { id: u.user.id } })).toBe(1);
    const retry = await request(t.app)
      .delete('/api/me')
      .set('Authorization', bearer(u.accessToken))
      .send({ authKey: u.authKey });
    expect(retry.status).toBe(204);
  });
});
