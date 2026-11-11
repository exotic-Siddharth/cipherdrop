/**
 * Recipient side: meta (410 reasons), unlock, open (atomic consumption: 10 concurrent opens on
 * maxDownloads=1 -> exactly 1 success), chunk GET (grants, R12 sliding expiry), and a full lifecycle with
 * real @cipherdrop/crypto encryption.
 */
import {
  b64urlEncode,
  chunkCount as cryptoChunkCount,
  createChunkDecryptor,
  decryptManifest,
  deriveFileKey,
  encryptChunk,
  encryptManifest,
  generateDropKey,
  generateFileId,
  type Manifest,
} from '@cipherdrop/crypto';
import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createUserRecord } from '../../../test/factories';
import { sha256B64url } from '../../lib/hash';
import {
  complete,
  createDropOk,
  createReadyDrop,
  fakeWrappedKey,
  getChunk,
  HOUR,
  MIN,
  openDrop,
  passwordFixture,
  putChunk,
  sha256Hex,
  testClock,
  testFile,
  token32,
  id16,
  metricValue,
} from './test-utils';

const MiB = 1024 * 1024;
const T0 = new Date('2026-11-08T12:00:00.000Z');

describe('drop download', () => {
  let t: TestApp;
  const clock = testClock(T0);

  beforeAll(async () => {
    t = await createTestApp({ now: clock.now });
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(() => {
    clock.set(T0);
  });

  const meta = (id: string) => request(t.app).get(`/api/drops/${id}`);

  describe('GET /drops/:id', () => {
    it('returns DropMeta for a READY drop', async () => {
      const files = [testFile(10), testFile(4 * MiB + 1)];
      const drop = await createReadyDrop(t.app, {
        files,
        body: { maxDownloads: 3, expiresInHours: 6 },
      });
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      const res = await meta(drop.dropId);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        id: drop.dropId,
        status: 'READY',
        fileCount: 2,
        totalBytes: files[0]!.ciphertextBytes + files[1]!.ciphertextBytes,
        expiresAt: new Date(T0.getTime() + 6 * HOUR).toISOString(),
        maxDownloads: 3,
        downloadsRemaining: 3,
        passwordProtected: false,
        encryptedManifest: row.encryptedManifest,
        passwordKdf: null,
        createdAt: T0.toISOString(),
      });
      expect(res.headers['cache-control']).toContain('no-store');
    });

    it('hides the manifest of a password drop and exposes its KDF params', async () => {
      const pw = passwordFixture();
      const drop = await createReadyDrop(t.app, { body: { password: pw.password } });
      const res = await meta(drop.dropId);
      expect(res.status).toBe(200);
      expect(res.body.passwordProtected).toBe(true);
      expect(res.body.encryptedManifest).toBeNull();
      expect(res.body.passwordKdf).toEqual(pw.password.kdf);
      expect(JSON.stringify(res.body)).not.toContain(pw.password.wrappedDropKey);
      expect(JSON.stringify(res.body)).not.toContain(pw.password.authKeyHash);
    });

    it('answers 404 for an unknown drop and for one still uploading', async () => {
      expect((await meta(id16())).status).toBe(404);
      const uploading = await createDropOk(t.app, {
        encryptedManifest: randomBytes(60).toString('base64url'),
        files: [{ id: id16(), ciphertextBytes: 20, chunkCount: 1 }],
        expiresInHours: 1,
        maxDownloads: 1,
      });
      expect((await meta(uploading.dropId)).status).toBe(404);
      expect((await meta('not-a-drop-id')).status).toBe(400);
    });

    it('answers 410 GONE with the reason (EXPIRED, EXHAUSTED, DELETED, DISABLED)', async () => {
      const expired = await createReadyDrop(t.app, { body: { expiresInHours: 1 } });
      clock.advance(HOUR);
      let res = await meta(expired.dropId);
      expect(res.status).toBe(410);
      expect(res.body.error).toMatchObject({ code: 'GONE', details: { reason: 'EXPIRED' } });
      clock.set(T0);

      for (const status of ['EXPIRED', 'EXHAUSTED', 'DELETED', 'DISABLED'] as const) {
        const d = await createReadyDrop(t.app);
        await t.prisma.drop.update({ where: { id: d.dropId }, data: { status } });
        res = await meta(d.dropId);
        expect(res.status).toBe(410);
        expect(res.body.error.details).toEqual({ reason: status });
      }
    });
  });

  describe('POST /drops/:id/unlock', () => {
    it('releases the wrapped key and manifest for the right authKey', async () => {
      const pw = passwordFixture();
      const drop = await createReadyDrop(t.app, { body: { password: pw.password } });
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      const res = await request(t.app)
        .post(`/api/drops/${drop.dropId}/unlock`)
        .send({ authKey: pw.authKey });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        wrappedDropKey: pw.password.wrappedDropKey,
        encryptedManifest: row.encryptedManifest,
      });
    });

    it('answers 401 for a wrong key and audits DROP_UNLOCK_FAILED to the owner', async () => {
      const user = await createUserRecord(t.prisma);
      const pw = passwordFixture();
      const drop = await createReadyDrop(t.app, {
        body: { password: pw.password, ownerWrappedKey: fakeWrappedKey() },
        headers: { Authorization: authHeader(user) },
      });
      const res = await request(t.app)
        .post(`/api/drops/${drop.dropId}/unlock`)
        .set('X-Forwarded-For', '203.0.113.9')
        .send({ authKey: token32() });
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(JSON.stringify(res.body)).not.toContain(pw.password.wrappedDropKey);
      const ev = await t.prisma.auditEvent.findFirstOrThrow({
        where: { userId: user.id, action: 'DROP_UNLOCK_FAILED' },
      });
      expect(ev.dropId).toBe(drop.dropId);
      expect(ev.ipPrefix).toBe('203.0.113.0/24');
    });

    it('rejects a malformed authKey (400), a non-password drop (400) and gone drops (410)', async () => {
      const pw = passwordFixture();
      const drop = await createReadyDrop(t.app, { body: { password: pw.password } });
      expect(
        (await request(t.app).post(`/api/drops/${drop.dropId}/unlock`).send({ authKey: 'short' }))
          .status,
      ).toBe(400);
      const plain = await createReadyDrop(t.app);
      expect(
        (
          await request(t.app)
            .post(`/api/drops/${plain.dropId}/unlock`)
            .send({ authKey: token32() })
        ).status,
      ).toBe(400);
      await t.prisma.drop.update({ where: { id: drop.dropId }, data: { status: 'DISABLED' } });
      const gone = await request(t.app)
        .post(`/api/drops/${drop.dropId}/unlock`)
        .send({ authKey: pw.authKey });
      expect(gone.status).toBe(410);
    });

    it('is rate limited per drop+IP (5 per 15 min)', async () => {
      const rl = await createTestApp({ rateLimits: { unlockDropIp: true, unlockDrop: true } });
      try {
        const pw = passwordFixture();
        const drop = await createReadyDrop(rl.app, { body: { password: pw.password } });
        const ip = { 'X-Forwarded-For': '198.51.100.200' };
        for (let i = 0; i < 5; i++) {
          const res = await request(rl.app)
            .post(`/api/drops/${drop.dropId}/unlock`)
            .set(ip)
            .send({ authKey: token32() });
          expect(res.status).toBe(401);
        }
        const blocked = await request(rl.app)
          .post(`/api/drops/${drop.dropId}/unlock`)
          .set(ip)
          .send({ authKey: pw.authKey });
        expect(blocked.status).toBe(429);
        expect(blocked.body.error.code).toBe('RATE_LIMITED');
        // A different IP can still unlock.
        const other = await request(rl.app)
          .post(`/api/drops/${drop.dropId}/unlock`)
          .set('X-Forwarded-For', '198.51.100.201')
          .send({ authKey: pw.authKey });
        expect(other.status).toBe(200);
      } finally {
        await rl.close();
      }
    });
  });

  describe('password guess limits (/unlock and /open share failure buckets)', () => {
    const unlockPost = (app: TestApp['app'], id: string, ip: string, authKey: string) =>
      request(app).post(`/api/drops/${id}/unlock`).set('X-Forwarded-For', ip).send({ authKey });
    const openPost = (app: TestApp['app'], id: string, ip: string, authKey: string) =>
      openDrop(app, id, { authKey }, { 'X-Forwarded-For': ip });
    const ips = (n: number) => Array.from({ length: n }, (_, i) => `198.51.100.${i + 1}`);

    it('wrong keys on /open from many IPs hit the per-drop cap (20/h), like /unlock', async () => {
      const rl = await createTestApp({ rateLimits: { unlockDropIp: true, unlockDrop: true } });
      try {
        const pw = passwordFixture();
        const drop = await createReadyDrop(rl.app, { body: { password: pw.password } });
        const statuses: number[] = [];
        for (const ip of ips(25)) {
          statuses.push((await openPost(rl.app, drop.dropId, ip, token32())).status);
        }
        expect(statuses.slice(0, 20).every((s) => s === 401)).toBe(true);
        expect(statuses.slice(20).every((s) => s === 429)).toBe(true);
        // The cap also blocks the right key, and says nothing about the password.
        const blocked = await openPost(rl.app, drop.dropId, '198.51.100.99', pw.authKey);
        expect(blocked.status).toBe(429);
        expect(blocked.body.error.code).toBe('RATE_LIMITED');
        expect(await rl.prisma.downloadGrant.count({ where: { dropId: drop.dropId } })).toBe(0);
      } finally {
        await rl.close();
      }
    });

    it('guesses on /unlock and /open draw from one budget', async () => {
      const rl = await createTestApp({ rateLimits: { unlockDropIp: true, unlockDrop: true } });
      try {
        const pw = passwordFixture();
        const drop = await createReadyDrop(rl.app, { body: { password: pw.password } });
        const list = ips(22);
        for (const ip of list.slice(0, 10)) {
          expect((await unlockPost(rl.app, drop.dropId, ip, token32())).status).toBe(401);
        }
        for (const ip of list.slice(10, 20)) {
          expect((await openPost(rl.app, drop.dropId, ip, token32())).status).toBe(401);
        }
        expect((await unlockPost(rl.app, drop.dropId, list[20]!, token32())).status).toBe(429);
        expect((await openPost(rl.app, drop.dropId, list[21]!, token32())).status).toBe(429);
      } finally {
        await rl.close();
      }
    });

    it('correct keys never use up the budget (25 unlocks and 25 opens from 25 IPs)', async () => {
      const rl = await createTestApp({ rateLimits: { unlockDropIp: true, unlockDrop: true } });
      try {
        const pw = passwordFixture();
        const user = await createUserRecord(rl.prisma);
        const drop = await createReadyDrop(rl.app, {
          body: { password: pw.password, maxDownloads: 50, ownerWrappedKey: fakeWrappedKey() },
          headers: { Authorization: authHeader(user) },
        });
        for (const ip of ips(25)) {
          expect((await unlockPost(rl.app, drop.dropId, ip, pw.authKey)).status).toBe(200);
          expect((await openPost(rl.app, drop.dropId, ip, pw.authKey)).status).toBe(200);
        }
        // ...and the first wrong guess afterwards is still a plain 401.
        expect((await unlockPost(rl.app, drop.dropId, '198.51.100.200', token32())).status).toBe(
          401,
        );
      } finally {
        await rl.close();
      }
    });

    it('does not throttle opens of a drop without a password', async () => {
      const rl = await createTestApp({ rateLimits: { unlockDropIp: true, unlockDrop: true } });
      try {
        const user = await createUserRecord(rl.prisma);
        const drop = await createReadyDrop(rl.app, {
          body: { maxDownloads: 50, ownerWrappedKey: fakeWrappedKey() },
          headers: { Authorization: authHeader(user) },
        });
        for (let i = 0; i < 25; i++) {
          expect((await openDrop(rl.app, drop.dropId)).status).toBe(200);
        }
      } finally {
        await rl.close();
      }
    });
  });

  describe('POST /drops/:id/open', () => {
    it('10 concurrent opens on maxDownloads=1 give exactly one success', async () => {
      const drop = await createReadyDrop(t.app, { body: { maxDownloads: 1 } });
      const results = await Promise.all(
        Array.from({ length: 10 }, () => openDrop(t.app, drop.dropId)),
      );
      const ok = results.filter((r) => r.status === 200);
      expect(ok).toHaveLength(1);
      expect(ok[0]!.body.downloadsRemaining).toBe(0);
      for (const r of results.filter((x) => x.status !== 200)) {
        expect(r.status).toBe(410);
        expect(r.body.error.details).toEqual({ reason: 'EXHAUSTED' });
      }
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.downloadCount).toBe(1);
      expect(row.status).toBe('EXHAUSTED');
      expect(await t.prisma.downloadGrant.count({ where: { dropId: drop.dropId } })).toBe(1);
    });

    it('counts downloadsRemaining down and then answers 410 EXHAUSTED', async () => {
      const drop = await createReadyDrop(t.app, { body: { maxDownloads: 3 } });
      const before = await metricValue(t.app, 'drop_opens_total');
      const remaining: number[] = [];
      for (let i = 0; i < 3; i++) {
        const res = await openDrop(t.app, drop.dropId);
        expect(res.status).toBe(200);
        expect(res.body).toEqual({
          downloadToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
          expiresAt: new Date(T0.getTime() + 30 * MIN).toISOString(),
          downloadsRemaining: expect.any(Number),
        });
        remaining.push(res.body.downloadsRemaining);
      }
      expect(remaining).toEqual([2, 1, 0]);
      expect((await metricValue(t.app, 'drop_opens_total')) - before).toBe(3);
      const res = await openDrop(t.app, drop.dropId);
      expect(res.status).toBe(410);
      expect(res.body.error.details.reason).toBe('EXHAUSTED');
      expect((await meta(drop.dropId)).body.error.details.reason).toBe('EXHAUSTED');
      // Grants are stored only as hashes.
      const grants = await t.prisma.downloadGrant.findMany({ where: { dropId: drop.dropId } });
      expect(grants).toHaveLength(3);
      expect(grants.every((g) => g.tokenHash.length === 43 && !g.isAdmin)).toBe(true);
    });

    it('requires the authKey for a password drop', async () => {
      const pw = passwordFixture();
      const drop = await createReadyDrop(t.app, {
        body: { password: pw.password, maxDownloads: 2 },
      });
      expect((await openDrop(t.app, drop.dropId)).status).toBe(401);
      expect((await openDrop(t.app, drop.dropId, { authKey: token32() })).status).toBe(401);
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.downloadCount).toBe(0);
      const ok = await openDrop(t.app, drop.dropId, { authKey: pw.authKey });
      expect(ok.status).toBe(200);
      expect(ok.body.downloadsRemaining).toBe(1);
    });

    it('audits DROP_OPENED to the owner with the ipPrefix and UA summary', async () => {
      const user = await createUserRecord(t.prisma);
      const drop = await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: { Authorization: authHeader(user) },
      });
      const res = await openDrop(
        t.app,
        drop.dropId,
        {},
        {
          'X-Forwarded-For': '2001:db8:abcd:12::1',
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36',
        },
      );
      expect(res.status).toBe(200);
      const ev = await t.prisma.auditEvent.findFirstOrThrow({
        where: { userId: user.id, action: 'DROP_OPENED' },
      });
      expect(ev.dropId).toBe(drop.dropId);
      expect(ev.ipPrefix).toBe('2001:db8:abcd::/48');
      expect(ev.userAgent).toBeTruthy();
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.lastOpenedAt?.toISOString()).toBe(T0.toISOString());
      const grant = await t.prisma.downloadGrant.findFirstOrThrow({
        where: { dropId: drop.dropId },
      });
      expect(grant.ipPrefix).toBe('2001:db8:abcd::/48');
    });

    it('answers 404 for unknown drops and 410 for expired ones', async () => {
      expect((await openDrop(t.app, id16())).status).toBe(404);
      const drop = await createReadyDrop(t.app, { body: { expiresInHours: 1 } });
      clock.advance(HOUR + 1);
      const res = await openDrop(t.app, drop.dropId);
      expect(res.status).toBe(410);
      expect(res.body.error.details.reason).toBe('EXPIRED');
    });

    it('is rate limited per IP (30/h)', async () => {
      const rl = await createTestApp({ rateLimits: { open: true } });
      try {
        const drop = await createReadyDrop(rl.app, { body: { maxDownloads: 1 } });
        const res = await openDrop(rl.app, drop.dropId, {}, { 'X-Forwarded-For': '192.0.2.10' });
        expect(res.status).toBe(200);
        expect(String(res.headers['ratelimit-policy'])).toContain('30');
      } finally {
        await rl.close();
      }
    });
  });

  describe('GET /drops/:id/files/:fileId/chunks/:index', () => {
    it('streams the exact stored bytes with Content-Length', async () => {
      const f = testFile(4 * MiB + 33);
      const drop = await createReadyDrop(t.app, { files: [f] });
      const { downloadToken } = (await openDrop(t.app, drop.dropId)).body;
      const before = await metricValue(t.app, 'chunk_bytes_downloaded_total');
      for (let i = 0; i < f.chunkCount; i++) {
        const res = await getChunk(t.app, drop.dropId, downloadToken, f.id, i);
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toBe('application/octet-stream');
        expect(Number(res.headers['content-length'])).toBe(f.chunkSizes[i]);
        expect((res.body as Buffer).equals(drop.chunks.get(f.id)![i]!)).toBe(true);
      }
      expect((await metricValue(t.app, 'chunk_bytes_downloaded_total')) - before).toBe(
        f.ciphertextBytes,
      );
    });

    it('requires a valid grant for that drop', async () => {
      const a = await createReadyDrop(t.app);
      const b = await createReadyDrop(t.app);
      const fileId = a.files[0]!.id;
      expect((await getChunk(t.app, a.dropId, null, fileId, 0)).status).toBe(401);
      expect((await getChunk(t.app, a.dropId, token32(), fileId, 0)).status).toBe(401);
      expect((await getChunk(t.app, a.dropId, a.ownerToken, fileId, 0)).status).toBe(401);
      const grantB = (await openDrop(t.app, b.dropId)).body.downloadToken as string;
      expect((await getChunk(t.app, a.dropId, grantB, fileId, 0)).status).toBe(401);
    });

    it('answers 404 for an unknown file or index', async () => {
      const a = await createReadyDrop(t.app);
      const tok = (await openDrop(t.app, a.dropId)).body.downloadToken as string;
      expect((await getChunk(t.app, a.dropId, tok, id16(), 0)).status).toBe(404);
      expect((await getChunk(t.app, a.dropId, tok, a.files[0]!.id, 1)).status).toBe(404);
    });

    it('rejects an expired grant with 401', async () => {
      const a = await createReadyDrop(t.app);
      const tok = (await openDrop(t.app, a.dropId)).body.downloadToken as string;
      clock.advance(30 * MIN);
      expect((await getChunk(t.app, a.dropId, tok, a.files[0]!.id, 0)).status).toBe(401);
    });

    it('slides the grant on each chunk GET, capped at createdAt + 24 h (R12)', async () => {
      const f = testFile(10);
      const a = await createReadyDrop(t.app, { files: [f], body: { expiresInHours: 72 } });
      const tok = (await openDrop(t.app, a.dropId)).body.downloadToken as string;
      const where = { tokenHash: sha256B64url(tok) };
      clock.advance(20 * MIN);
      expect((await getChunk(t.app, a.dropId, tok, f.id, 0)).status).toBe(200);
      expect(
        (await t.prisma.downloadGrant.findUniqueOrThrow({ where })).expiresAt.toISOString(),
      ).toBe(new Date(T0.getTime() + 50 * MIN).toISOString());
      // Keep using it for almost 24 h: the expiry never passes createdAt + 24 h.
      for (let i = 0; i < 50; i++) {
        clock.advance(29 * MIN);
        const res = await getChunk(t.app, a.dropId, tok, f.id, 0);
        if (clock.now().getTime() >= T0.getTime() + 24 * HOUR) {
          expect(res.status).toBe(401);
          break;
        }
        expect(res.status).toBe(200);
        const g = await t.prisma.downloadGrant.findUniqueOrThrow({ where });
        expect(g.expiresAt.getTime()).toBeLessThanOrEqual(T0.getTime() + 24 * HOUR);
      }
      const g = await t.prisma.downloadGrant.findUniqueOrThrow({ where });
      expect(g.expiresAt.toISOString()).toBe(new Date(T0.getTime() + 24 * HOUR).toISOString());
    });

    it('keeps an EXHAUSTED drop downloadable while the grant lives', async () => {
      const a = await createReadyDrop(t.app, { body: { maxDownloads: 1 } });
      const tok = (await openDrop(t.app, a.dropId)).body.downloadToken as string;
      expect((await t.prisma.drop.findUniqueOrThrow({ where: { id: a.dropId } })).status).toBe(
        'EXHAUSTED',
      );
      clock.advance(10 * MIN);
      const res = await getChunk(t.app, a.dropId, tok, a.files[0]!.id, 0);
      expect(res.status).toBe(200);
      expect((res.body as Buffer).equals(a.chunks.get(a.files[0]!.id)![0]!)).toBe(true);
    });

    it('refuses chunks of a DELETED or DISABLED drop even with a live grant (410)', async () => {
      for (const status of ['DELETED', 'DISABLED'] as const) {
        const a = await createReadyDrop(t.app);
        const tok = (await openDrop(t.app, a.dropId)).body.downloadToken as string;
        await t.prisma.drop.update({ where: { id: a.dropId }, data: { status } });
        const res = await getChunk(t.app, a.dropId, tok, a.files[0]!.id, 0);
        expect(res.status).toBe(410);
      }
    });
  });

  it('full lifecycle with real client crypto: encrypt, upload, open, download, decrypt', async () => {
    const dk = generateDropKey();
    const plaintext = new Uint8Array(randomBytes(3 * 1024 + 5));
    const fileId = generateFileId();
    const count = cryptoChunkCount(plaintext.length);
    const manifest: Manifest = {
      v: 1,
      createdAt: T0.getTime(),
      note: null,
      files: [
        {
          id: fileId,
          name: 'report final (2).pdf',
          size: plaintext.length,
          type: 'application/pdf',
          lastModified: T0.getTime(),
          chunkSize: 4 * MiB,
          chunkCount: count,
        },
      ],
    };
    const encryptedManifest = await encryptManifest(dk, manifest);
    const key = await deriveFileKey(dk, fileId);
    const ct = Buffer.from(await encryptChunk(key, 0, true, plaintext));

    const created = await createDropOk(t.app, {
      encryptedManifest,
      files: [{ id: fileId, ciphertextBytes: ct.length, chunkCount: count }],
      expiresInHours: 1,
      maxDownloads: 1,
    });
    expect((await putChunk(t.app, created.dropId, created.uploadToken, fileId, 0, ct)).status).toBe(
      204,
    );
    expect((await complete(t.app, created)).status).toBe(200);

    const m = await meta(created.dropId);
    const back = await decryptManifest(dk, m.body.encryptedManifest as string);
    expect(back.files[0]!.name).toBe('report final (2).pdf');

    const grant = await openDrop(t.app, created.dropId);
    const res = await getChunk(t.app, created.dropId, grant.body.downloadToken, fileId, 0);
    expect(sha256Hex(res.body as Buffer)).toBe(sha256Hex(ct));
    const dec = createChunkDecryptor(key, count);
    const pt = await dec.decryptNext(new Uint8Array(res.body as Buffer));
    expect(dec.done()).toBe(true);
    expect(b64urlEncode(pt)).toBe(b64urlEncode(plaintext));

    // Nothing the server stored contains the file name.
    const rows = JSON.stringify(
      await t.prisma.drop.findUniqueOrThrow({
        where: { id: created.dropId },
        include: { files: true, chunks: true },
      }),
      (_k, v: unknown) => (typeof v === 'bigint' ? Number(v) : v),
    );
    expect(rows).not.toContain('report final');
  });
});
