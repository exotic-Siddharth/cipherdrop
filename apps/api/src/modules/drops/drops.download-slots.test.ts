/**
 * C-R2-04: one client with one grant must not hold every storage stream (S3 socket). Chunk GETs in flight are
 * capped per grant, per IP and per process (429 + Retry-After beyond), and a slot is released on finish,
 * storage error, idle abort and client disconnect.
 */
import http, { type ClientRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import type { StorageDriver } from '../../storage';
import { createReadyDrop, getChunk, openDrop, testFile, type ReadyDrop } from './test-utils';

describe('C-R2-04: chunk GET in-flight caps', () => {
  let t: TestApp;
  let capped: TestApp;
  let server: ReturnType<TestApp['app']['listen']>;
  /** How the next getChunkStream behaves. */
  let mode: 'real' | 'endless' | 'error' | 'reject' = 'real';
  const streams: Readable[] = [];
  const held: ClientRequest[] = [];

  beforeAll(async () => {
    t = await createTestApp();
    await resetTables(t.prisma);
    const storage: StorageDriver = {
      ...t.storage,
      async getChunkStream(dropId, fileId, index, version) {
        if (mode === 'reject') throw new Error('probe: storage unavailable');
        if (mode === 'real') return t.storage.getChunkStream(dropId, fileId, index, version);
        let sent = 0;
        const failing = mode === 'error';
        const s = new Readable({
          read() {
            if (failing && sent > 0) {
              this.destroy(new Error('probe: storage stream failed'));
              return;
            }
            sent += 1;
            this.push(Buffer.alloc(64 * 1024, 1));
          },
        });
        streams.push(s);
        return s;
      },
    };
    capped = await createTestApp({
      storage,
      prisma: t.prisma,
      redis: t.redis,
      env: {
        MAX_CONCURRENT_CHUNK_DOWNLOADS: 3,
        MAX_CHUNK_DOWNLOADS_PER_GRANT: 1,
        MAX_CHUNK_DOWNLOADS_PER_IP: 2,
        CHUNK_IDLE_TIMEOUT_SEC: 1,
      },
    });
    server = capped.app.listen(0, '127.0.0.1');
    await new Promise<void>((r) => server.once('listening', () => r()));
  });
  afterEach(async () => {
    for (const req of held.splice(0)) req.destroy();
    for (const s of streams.splice(0)) s.destroy();
    mode = 'real';
    await sleep(200); // let the server see the closes and release the slots
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await capped.close();
    await t.close();
  });

  /** A READY drop with two files: chunk 0 of file 0 is declared huge, so a held GET of it never completes. */
  async function twoFileDrop(): Promise<ReadyDrop> {
    const drop = await createReadyDrop(t.app, { files: [testFile(1000), testFile(1000)] });
    await t.prisma.dropChunk.updateMany({
      where: { dropId: drop.dropId, fileId: drop.files[0]!.id },
      data: { size: 500 * 1024 * 1024 },
    });
    return drop;
  }

  async function grant(drop: ReadyDrop): Promise<string> {
    const res = await openDrop(t.app, drop.dropId);
    expect(res.status).toBe(200);
    return res.body.downloadToken as string;
  }

  /** GET the huge chunk from `ip` and never read it; resolves with the status once headers arrive. */
  function heldGet(drop: ReadyDrop, token: string, ip: string) {
    const req = http.get({
      host: '127.0.0.1',
      port: (server.address() as AddressInfo).port,
      path: `/api/drops/${drop.dropId}/files/${drop.files[0]!.id}/chunks/0`,
      headers: { Authorization: `Bearer ${token}`, 'X-Forwarded-For': ip },
    });
    held.push(req);
    req.on('error', () => {});
    const closed = new Promise<void>((r) => req.on('close', () => r()));
    const status = new Promise<number>((resolve) => {
      req.on('response', (res) => {
        res.pause(); // never read the body
        resolve(res.statusCode ?? 0);
      });
      req.on('close', () => resolve(0));
    });
    return { req, status, closed };
  }

  /** GET the small chunk (file 1) from `ip` with real storage. */
  const smallGet = (drop: ReadyDrop, token: string, ip: string) => {
    mode = 'real';
    return getChunk(capped.app, drop.dropId, token, drop.files[1]!.id, 0).set(
      'X-Forwarded-For',
      ip,
    );
  };

  async function hold(drop: ReadyDrop, token: string, ip: string) {
    mode = 'endless';
    const h = heldGet(drop, token, ip);
    expect(await h.status).toBe(200);
    return h;
  }

  it('caps chunk GETs per grant; another grant from the same IP is unaffected', async () => {
    const drop = await twoFileDrop();
    const g1 = await grant(drop);
    await hold(drop, g1, '192.0.2.1');
    const refused = await smallGet(drop, g1, '192.0.2.1');
    expect(refused.status).toBe(429);
    expect(refused.headers['retry-after']).toBeDefined();
    const g2 = await grant(drop);
    expect((await smallGet(drop, g2, '192.0.2.1')).status).toBe(200);
  });

  it('caps chunk GETs per IP; the same grant from another IP is unaffected', async () => {
    const drop = await twoFileDrop();
    await hold(drop, await grant(drop), '192.0.2.2');
    await hold(drop, await grant(drop), '192.0.2.2');
    const g3 = await grant(drop);
    const refused = await smallGet(drop, g3, '192.0.2.2');
    expect(refused.status).toBe(429);
    expect(refused.headers['retry-after']).toBeDefined();
    expect((await smallGet(drop, g3, '192.0.2.3')).status).toBe(200);
  });

  it('C-R3-03: the per-IP share of chunk GETs covers an IPv6 /48, not each /64 inside it', async () => {
    const drop = await twoFileDrop();
    await hold(drop, await grant(drop), '2001:db8:9:1::1');
    await hold(drop, await grant(drop), '2001:db8:9:2::1');
    const g3 = await grant(drop);
    const refused = await smallGet(drop, g3, '2001:db8:9:3::1');
    expect(refused.status).toBe(429);
    expect((await smallGet(drop, g3, '2001:db8:a::1')).status).toBe(200);
  });

  it('caps chunk GETs per process (below the S3 socket pool)', async () => {
    const drop = await twoFileDrop();
    for (const ip of ['192.0.2.4', '192.0.2.5', '192.0.2.6'])
      await hold(drop, await grant(drop), ip);
    const refused = await smallGet(drop, await grant(drop), '192.0.2.7');
    expect(refused.status).toBe(429);
    expect(refused.headers['retry-after']).toBeDefined();
  });

  it('releases the slot when a GET finishes', async () => {
    const drop = await twoFileDrop();
    const g = await grant(drop);
    for (let i = 0; i < 3; i++) expect((await smallGet(drop, g, '192.0.2.8')).status).toBe(200);
  });

  it('releases the slot when the storage stream fails or getChunkStream rejects', async () => {
    const drop = await twoFileDrop();
    const g = await grant(drop);
    mode = 'error';
    const failed = heldGet(drop, g, '192.0.2.9');
    await failed.closed; // the server drops the connection mid-stream
    await sleep(100);
    mode = 'reject';
    const rejected = await getChunk(capped.app, drop.dropId, g, drop.files[1]!.id, 0).set(
      'X-Forwarded-For',
      '192.0.2.9',
    );
    expect(rejected.status).toBe(500);
    expect((await smallGet(drop, g, '192.0.2.9')).status).toBe(200);
  });

  it('releases the slot when the idle timeout aborts a stalled GET', async () => {
    const drop = await twoFileDrop();
    const g = await grant(drop);
    await hold(drop, g, '192.0.2.10');
    const deadline = Date.now() + 6000;
    while (Date.now() < deadline && !streams.every((s) => s.destroyed)) await sleep(100);
    expect(streams.every((s) => s.destroyed)).toBe(true);
    await sleep(100);
    expect((await smallGet(drop, g, '192.0.2.10')).status).toBe(200);
  });

  it('releases the slot when the client disconnects', async () => {
    const drop = await twoFileDrop();
    const g = await grant(drop);
    const h = await hold(drop, g, '192.0.2.11');
    h.req.destroy();
    await h.closed;
    await sleep(200);
    expect((await smallGet(drop, g, '192.0.2.11')).status).toBe(200);
  });
});
