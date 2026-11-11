/**
 * Local driver specifics: atomic writes (temp file + rename), R21 Windows retries, realpath'd root.
 */
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Readable } from 'node:stream';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { removeDir, tempStorageDir } from '../../test/storage';
import { createLocalStorage } from './local';

const id16 = () => randomBytes(16).toString('base64url');

async function readAll(stream: Readable): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const part of stream) parts.push(Buffer.from(part as Uint8Array));
  return Buffer.concat(parts);
}

function listFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { recursive: true, encoding: 'utf8' });
}

describe('local storage driver', () => {
  let dir: string;

  beforeAll(() => {
    dir = tempStorageDir('cipherdrop-local-');
  });
  afterAll(async () => {
    await removeDir(dir);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('init creates a missing root directory', async () => {
    const root = path.join(dir, 'nested', 'blobs');
    const storage = createLocalStorage(root);
    await storage.init();
    expect(fs.statSync(root).isDirectory()).toBe(true);
    await storage.healthCheck();
  });

  it('writes atomically: temp file in the same directory, then rename; no temp file remains', async () => {
    const storage = createLocalStorage(dir);
    await storage.init();
    const dropId = id16();
    const fileId = id16();
    const rename = vi.spyOn(fs.promises, 'rename');
    const data = randomBytes(5000);
    await storage.putChunk(dropId, fileId, 7, data);

    expect(rename).toHaveBeenCalledTimes(1);
    const [from, to] = rename.mock.calls[0] as [string, string];
    expect(path.dirname(String(from))).toBe(path.dirname(String(to)));
    expect(String(from)).not.toBe(String(to));
    expect(path.basename(String(to))).toBe('7');

    const files = listFiles(path.join(dir, dropId));
    expect(files.some((f) => f.includes('.tmp'))).toBe(false);
    expect((await readAll(await storage.getChunkStream(dropId, fileId, 7))).equals(data)).toBe(
      true,
    );
  });

  it('readers never see a partial chunk while it is overwritten', async () => {
    const storage = createLocalStorage(dir);
    await storage.init();
    const dropId = id16();
    const fileId = id16();
    const a = Buffer.alloc(512 * 1024, 0xaa);
    const b = Buffer.alloc(512 * 1024, 0xbb);
    await storage.putChunk(dropId, fileId, 0, a);

    const writes = Array.from({ length: 6 }, (_, i) =>
      storage.putChunk(dropId, fileId, 0, i % 2 ? a : b),
    );
    const reads = Array.from({ length: 12 }, async () =>
      readAll(await storage.getChunkStream(dropId, fileId, 0)),
    );
    const [, results] = await Promise.all([Promise.all(writes), Promise.all(reads)]);
    for (const got of results) {
      expect(got.length).toBe(a.length);
      expect(got.equals(a) || got.equals(b)).toBe(true);
    }
  });

  it('a failed write leaves the previous chunk intact and removes the temp file', async () => {
    const storage = createLocalStorage(dir);
    await storage.init();
    const dropId = id16();
    const fileId = id16();
    const original = randomBytes(100);
    await storage.putChunk(dropId, fileId, 0, original);

    const err = Object.assign(new Error('disk on fire'), { code: 'EIO' });
    vi.spyOn(fs.promises, 'rename').mockRejectedValue(err);
    await expect(storage.putChunk(dropId, fileId, 0, randomBytes(100))).rejects.toThrow(
      'disk on fire',
    );
    vi.restoreAllMocks();

    expect((await readAll(await storage.getChunkStream(dropId, fileId, 0))).equals(original)).toBe(
      true,
    );
    expect(listFiles(path.join(dir, dropId)).some((f) => f.includes('.tmp'))).toBe(false);
  });

  it('retries rename on transient EPERM/EACCES/EBUSY (R21)', async () => {
    const storage = createLocalStorage(dir);
    await storage.init();
    const dropId = id16();
    const fileId = id16();
    const realRename = fs.promises.rename.bind(fs.promises);
    let calls = 0;
    vi.spyOn(fs.promises, 'rename').mockImplementation(async (from, to) => {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error('busy'), { code: 'EBUSY' });
      if (calls === 2) throw Object.assign(new Error('perm'), { code: 'EPERM' });
      return realRename(from, to);
    });
    const data = randomBytes(64);
    await storage.putChunk(dropId, fileId, 0, data);
    expect(calls).toBe(3);
    vi.restoreAllMocks();
    expect((await readAll(await storage.getChunkStream(dropId, fileId, 0))).equals(data)).toBe(
      true,
    );
  });

  it('resolves the root with realpath before guarding paths', async () => {
    // A relative root with a ".." segment still lands inside the real directory.
    const storage = createLocalStorage(path.join(dir, 'x', '..', 'real-root'));
    await storage.init();
    const dropId = id16();
    const fileId = id16();
    await storage.putChunk(dropId, fileId, 0, randomBytes(8));
    expect(fs.existsSync(path.join(dir, 'real-root', dropId, fileId, '0'))).toBe(true);
  });

  it('deleteDrop removes the drop directory', async () => {
    const storage = createLocalStorage(dir);
    await storage.init();
    const dropId = id16();
    await storage.putChunk(dropId, id16(), 0, randomBytes(8));
    expect(fs.existsSync(path.join(dir, dropId))).toBe(true);
    await storage.deleteDrop(dropId);
    expect(fs.existsSync(path.join(dir, dropId))).toBe(false);
  });

  it('healthCheck rejects when the root is gone', async () => {
    const root = tempStorageDir('cipherdrop-gone-');
    const storage = createLocalStorage(root);
    await storage.init();
    await removeDir(root);
    await expect(storage.healthCheck()).rejects.toThrow();
  });
});
