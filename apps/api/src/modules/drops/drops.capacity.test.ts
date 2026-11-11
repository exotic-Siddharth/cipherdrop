/**
 * C-15: chunk PUT buffers up to 4 MiB in memory per request, so a global in-flight cap (429 + Retry-After
 * beyond it), a body inactivity timeout and an optional ceiling on anonymous storage bound memory and disk.
 */
import http, { type ClientRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createUserRecord } from '../../../test/factories';
import {
  chunkData,
  createBody,
  createDropOk,
  fakeWrappedKey,
  putChunk,
  sha256Hex,
  testFile,
} from './test-utils';

describe('upload capacity limits', () => {
  let t: TestApp;
  let server: ReturnType<TestApp['app']['listen']>;
  let port = 0;

  beforeAll(async () => {
    t = await createTestApp({
      env: {
        MAX_CONCURRENT_CHUNK_UPLOADS: 1,
        CHUNK_UPLOAD_IDLE_TIMEOUT_SEC: 1,
        ANON_TOTAL_PENDING_BYTES: 3000,
      },
    });
    await resetTables(t.prisma);
    server = t.app.listen(0, '127.0.0.1');
    await new Promise<void>((r) => server.once('listening', () => r()));
    port = (server.address() as AddressInfo).port;
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await t.close();
  });

  /** Start a chunk PUT whose body stops after `sent` bytes (a slow or stalled client). */
  function stalledPut(
    drop: { dropId: string; uploadToken: string },
    fileId: string,
    data: Buffer,
    sent = 100,
  ): { req: ClientRequest; closed: Promise<void> } {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'PUT',
      path: `/api/drops/${drop.dropId}/files/${fileId}/chunks/0`,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(data.length),
        'X-Chunk-SHA256': sha256Hex(data),
        Authorization: `Bearer ${drop.uploadToken}`,
      },
    });
    const closed = new Promise<void>((resolve) => {
      req.on('error', () => undefined);
      req.on('close', () => resolve());
    });
    req.write(data.subarray(0, sent));
    return { req, closed };
  }

  it('answers 429 with Retry-After beyond the in-flight cap and frees the slot when a client aborts', async () => {
    const f = testFile(2000);
    const first = await createDropOk(t.app, createBody([f]));
    const second = await createDropOk(t.app, createBody([testFile(10)]));
    const data = chunkData(f, 0);
    const slow = stalledPut(first, f.id, data, 100);
    await sleep(300);

    const g = testFile(10);
    const other = await createDropOk(t.app, createBody([g]));
    const blocked = await putChunk(
      t.app,
      other.dropId,
      other.uploadToken,
      g.id,
      0,
      chunkData(g, 0),
    );
    expect(blocked.status).toBe(429);
    expect(blocked.headers['retry-after']).toBeDefined();

    slow.req.destroy();
    await slow.closed;
    await sleep(200);
    const ok = await putChunk(t.app, other.dropId, other.uploadToken, g.id, 0, chunkData(g, 0));
    expect(ok.status).toBe(204);
    void second;
  });

  it('drops a connection that stops sending its body (inactivity timeout) and frees the slot', async () => {
    const f = testFile(2000);
    const drop = await createDropOk(t.app, createBody([f]));
    const slow = stalledPut(drop, f.id, chunkData(f, 0), 100);
    // The client keeps the socket open and sends nothing more; the server must hang up by itself.
    const outcome = await Promise.race([
      slow.closed.then(() => 'closed'),
      sleep(4000).then(() => 'still open'),
    ]);
    slow.req.destroy();
    expect(outcome).toBe('closed');

    const g = testFile(10);
    const other = await createDropOk(t.app, createBody([g]));
    expect(
      (await putChunk(t.app, other.dropId, other.uploadToken, g.id, 0, chunkData(g, 0))).status,
    ).toBe(204);
  });

  it('caps the pending bytes of anonymous drops (ANON_TOTAL_PENDING_BYTES); signed-in users are unaffected', async () => {
    const big = testFile(2000);
    await createDropOk(t.app, createBody([big]));
    const refused = await request(t.app)
      .post('/api/drops')
      .send(createBody([testFile(2000)]));
    expect(refused.status).toBe(413);
    expect(refused.body.error.code).toBe('QUOTA_EXCEEDED');

    const user = await createUserRecord(t.prisma);
    const signedIn = await request(t.app)
      .post('/api/drops')
      .set({ Authorization: authHeader(user) })
      .send(createBody([testFile(2000)], { ownerWrappedKey: fakeWrappedKey() }));
    expect(signedIn.status).toBe(201);
  });

  it('C-R2-06: parallel anonymous creates cannot overshoot ANON_TOTAL_PENDING_BYTES', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        request(t.app)
          .post('/api/drops')
          .send(createBody([testFile(2000)])),
      ),
    );
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    expect(statuses.filter((s) => s === 413)).toHaveLength(7);
    const held = await t.prisma.drop.aggregate({
      _sum: { totalCiphertextBytes: true },
      where: { ownerId: null },
    });
    expect(Number(held._sum.totalCiphertextBytes)).toBeLessThanOrEqual(3000);
  });

  it('C-R2-06: anonymous EXHAUSTED and EXPIRED drops count until their blobs are purged', async () => {
    for (const status of ['EXHAUSTED', 'EXPIRED'] as const) {
      await resetTables(t.prisma);
      const held = await createDropOk(t.app, createBody([testFile(2000)]));
      await t.prisma.drop.update({ where: { id: held.dropId }, data: { status } });
      const refused = await request(t.app)
        .post('/api/drops')
        .send(createBody([testFile(2000)]));
      expect(refused.status).toBe(413);
      await t.prisma.drop.update({
        where: { id: held.dropId },
        data: { blobsDeletedAt: new Date() },
      });
      const accepted = await request(t.app)
        .post('/api/drops')
        .send(createBody([testFile(2000)]));
      expect(accepted.status).toBe(201);
    }
  });

  it('exposes the free space of the blob volume as a gauge after /readyz', async () => {
    expect((await request(t.app).get('/readyz')).status).toBe(200);
    const metrics = await request(t.app).get('/metrics');
    const m = /^storage_free_bytes\s+(\S+)$/m.exec(String(metrics.text));
    expect(m).not.toBeNull();
    expect(Number(m?.[1])).toBeGreaterThan(0);
  });
});

describe('C-R2-02: chunk PUT body deadline and per-token / per-IP shares of the in-flight slots', () => {
  let t: TestApp;
  let server: ReturnType<TestApp['app']['listen']>;
  let port = 0;
  const open: ClientRequest[] = [];

  beforeAll(async () => {
    t = await createTestApp({
      env: {
        MAX_CONCURRENT_CHUNK_UPLOADS: 10,
        MAX_CHUNK_UPLOADS_PER_TOKEN: 1,
        MAX_CHUNK_UPLOADS_PER_IP: 2,
        CHUNK_UPLOAD_IDLE_TIMEOUT_SEC: 1,
        CHUNK_UPLOAD_DEADLINE_SEC: 2,
      },
    });
    await resetTables(t.prisma);
    server = t.app.listen(0, '127.0.0.1');
    await new Promise<void>((r) => server.once('listening', () => r()));
    port = (server.address() as AddressInfo).port;
  });
  afterEach(async () => {
    for (const req of open.splice(0)) req.destroy();
    await sleep(200); // let the server see the closes and release the slots
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await t.close();
  });

  /** A chunk PUT from `ip` that sends `sent` bytes of its body, then nothing (unless the caller drips). */
  function heldPut(
    drop: { dropId: string; uploadToken: string },
    fileId: string,
    data: Buffer,
    ip: string,
    sent = 100,
  ): { req: ClientRequest; closed: Promise<void>; status: Promise<number> } {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'PUT',
      path: `/api/drops/${drop.dropId}/files/${fileId}/chunks/0`,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(data.length),
        'X-Chunk-SHA256': sha256Hex(data),
        'X-Forwarded-For': ip,
        Authorization: `Bearer ${drop.uploadToken}`,
      },
    });
    open.push(req);
    req.on('error', () => undefined);
    const closed = new Promise<void>((resolve) => req.on('close', () => resolve()));
    const status = new Promise<number>((resolve) => {
      req.on('response', (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on('close', () => resolve(0));
    });
    req.write(data.subarray(0, sent));
    return { req, closed, status };
  }

  const smallPut = (
    drop: { dropId: string; uploadToken: string },
    g: ReturnType<typeof testFile>,
    ip: string,
  ) =>
    putChunk(t.app, drop.dropId, drop.uploadToken, g.id, 0, chunkData(g, 0)).set(
      'X-Forwarded-For',
      ip,
    );

  it('hangs up a slow-drip body that misses CHUNK_UPLOAD_DEADLINE_SEC even though bytes keep arriving', async () => {
    const f = testFile(2000);
    const drop = await createDropOk(t.app, createBody([f]));
    const data = chunkData(f, 0);
    const slow = heldPut(drop, f.id, data, '198.51.100.1', 1);
    let sent = 1;
    const drip = setInterval(() => {
      if (sent < data.length - 1) slow.req.write(data.subarray(sent, ++sent));
    }, 300); // always under the 1 s idle timeout
    try {
      const outcome = await Promise.race([
        slow.closed.then(() => 'closed'),
        sleep(5000).then(() => 'still open'),
      ]);
      expect(outcome).toBe('closed');
    } finally {
      clearInterval(drip);
    }
  });

  it('caps in-flight chunk PUTs per upload token (429 + Retry-After); other tokens are unaffected', async () => {
    const f = testFile(2000);
    const drop = await createDropOk(t.app, createBody([f]));
    heldPut(drop, f.id, chunkData(f, 0), '198.51.100.2');
    await sleep(300);
    const again = await putChunk(
      t.app,
      drop.dropId,
      drop.uploadToken,
      f.id,
      0,
      chunkData(f, 0),
    ).set('X-Forwarded-For', '198.51.100.3');
    expect(again.status).toBe(429);
    expect(again.headers['retry-after']).toBeDefined();
    const g = testFile(10);
    const other = await createDropOk(t.app, createBody([g]));
    expect((await smallPut(other, g, '198.51.100.2')).status).toBe(204);
  });

  it('caps in-flight chunk PUTs per IP (429 + Retry-After) and frees the share when a client aborts', async () => {
    const ip = '198.51.100.4';
    const held = [];
    for (let i = 0; i < 2; i++) {
      const f = testFile(2000);
      const drop = await createDropOk(t.app, createBody([f]));
      held.push(heldPut(drop, f.id, chunkData(f, 0), ip));
    }
    await sleep(300);
    const g = testFile(10);
    const third = await createDropOk(t.app, createBody([g]));
    const refused = await smallPut(third, g, ip);
    expect(refused.status).toBe(429);
    expect(refused.headers['retry-after']).toBeDefined();
    expect((await smallPut(third, g, '198.51.100.5')).status).toBe(204);

    held[0]!.req.destroy();
    await held[0]!.closed;
    await sleep(200);
    expect((await smallPut(third, g, ip)).status).toBe(204);
  });
});
