/**
 * A chunk GET whose client never reads must not hold its storage stream (an S3 socket) forever: after
 * CHUNK_IDLE_TIMEOUT_SEC without progress the stream is destroyed and the response dropped.
 */
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import type { StorageDriver } from '../../storage';
import { createReadyDrop, openDrop } from './test-utils';

describe('stalled chunk GET', () => {
  let t: TestApp;
  let stalled: TestApp;
  let server: ReturnType<TestApp['app']['listen']>;
  const streams: Readable[] = [];

  beforeAll(async () => {
    t = await createTestApp();
    await resetTables(t.prisma);
    const storage: StorageDriver = {
      ...t.storage,
      // An endless 64 KiB-per-read stream: it only stops being read when the response stops accepting data.
      async getChunkStream() {
        const s = new Readable({
          read() {
            this.push(Buffer.alloc(64 * 1024, 1));
          },
        });
        streams.push(s);
        return s;
      },
    };
    stalled = await createTestApp({
      storage,
      prisma: t.prisma,
      redis: t.redis,
      env: { CHUNK_IDLE_TIMEOUT_SEC: 1 },
    });
    server = stalled.app.listen(0, '127.0.0.1');
    await new Promise<void>((r) => server.once('listening', () => r()));
  });
  afterAll(async () => {
    for (const s of streams) s.destroy();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await stalled.close();
    await t.close();
  });

  it('destroys the storage stream and closes the response when the client reads nothing', async () => {
    const drop = await createReadyDrop(t.app);
    // Declare a huge chunk so the endless stream is never "complete" from the client's point of view.
    await t.prisma.dropChunk.updateMany({
      where: { dropId: drop.dropId },
      data: { size: 500 * 1024 * 1024 },
    });
    const open = await openDrop(t.app, drop.dropId);
    const token = open.body.downloadToken as string;
    const port = (server.address() as AddressInfo).port;
    const req = http.get({
      host: '127.0.0.1',
      port,
      path: `/api/drops/${drop.dropId}/files/${drop.files[0]!.id}/chunks/0`,
      headers: { Authorization: `Bearer ${token}` },
    });
    req.on('error', () => {});
    req.on('response', (res) => res.pause()); // never read the body
    // The server-side storage stream must be destroyed by the idle timeout (1 s here), not stay open.
    const deadline = Date.now() + 6000;
    while (Date.now() < deadline && !(streams.length > 0 && streams.every((s) => s.destroyed))) {
      await sleep(100);
    }
    req.destroy();
    expect(streams.length).toBeGreaterThan(0);
    expect(streams.every((s) => s.destroyed)).toBe(true);
  }, 20_000);

  it('C-R2-03: keeps the keep-alive idle timeout after a chunk GET (the server closes the idle socket)', async () => {
    const drop = await createReadyDrop(t.app);
    const open = await openDrop(t.app, drop.dropId);
    const token = open.body.downloadToken as string;
    const plain = t.app.listen(0, '127.0.0.1');
    await new Promise<void>((r) => plain.once('listening', () => r()));
    plain.keepAliveTimeout = 500;
    // A raw socket: only the SERVER can close it (an http.Agent would honour the Keep-Alive hint itself).
    const CRLF = String.fromCharCode(13, 10);
    const socket = net.connect((plain.address() as AddressInfo).port, '127.0.0.1');
    try {
      let received = '';
      const closedByServer = new Promise<string>((r) => socket.once('end', () => r('closed')));
      const answered = new Promise<void>((resolve) => {
        socket.on('data', (c: Buffer) => {
          received += c.toString('latin1');
          if (received.includes(CRLF + CRLF)) resolve();
        });
      });
      socket.write(
        [
          `GET /api/drops/${drop.dropId}/files/${drop.files[0]!.id}/chunks/0 HTTP/1.1`,
          'Host: 127.0.0.1',
          'Connection: keep-alive',
          `Authorization: Bearer ${token}`,
          '',
          '',
        ].join(CRLF),
      );
      await answered;
      expect(received.startsWith('HTTP/1.1 200')).toBe(true);
      const outcome = await Promise.race([closedByServer, sleep(4000).then(() => 'still open')]);
      expect(outcome).toBe('closed');
    } finally {
      socket.destroy();
      plain.closeAllConnections();
      await new Promise<void>((r) => plain.close(() => r()));
    }
  }, 20_000);
});
