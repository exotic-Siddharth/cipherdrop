/**
 * Storage driver contract (spec section 14): the same suite runs against `local` (always) and `s3`
 * (only with S3_TEST=1, against the compose MinIO on 59000; R17).
 */
import { randomBytes } from 'node:crypto';
import type { Readable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { removeDir, tempStorageDir } from '../../test/storage';
import { isAppError } from '../lib/errors';
import { createStorage, type StorageDriver, type StorageEnv } from './index';

const id16 = () => randomBytes(16).toString('base64url');

async function readAll(stream: Readable): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const part of stream) parts.push(Buffer.from(part as Uint8Array));
  return Buffer.concat(parts);
}

async function expectNotFound(p: Promise<unknown>): Promise<void> {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(isAppError(err)).toBe(true);
  expect((err as { code?: string }).code).toBe('NOT_FOUND');
}

interface DriverCase {
  name: string;
  enabled: boolean;
  make: () => { env: StorageEnv; cleanup: () => Promise<void> };
}

const baseEnv: StorageEnv = {
  STORAGE_DRIVER: 'local',
  STORAGE_DIR: '',
  S3_ENDPOINT: undefined,
  S3_REGION: 'us-east-1',
  S3_BUCKET: 'cipherdrop',
  S3_ACCESS_KEY_ID: undefined,
  S3_SECRET_ACCESS_KEY: undefined,
  S3_FORCE_PATH_STYLE: true,
};

const cases: DriverCase[] = [
  {
    name: 'local',
    enabled: true,
    make: () => {
      const dir = tempStorageDir('cipherdrop-contract-');
      return {
        env: { ...baseEnv, STORAGE_DRIVER: 'local', STORAGE_DIR: dir },
        cleanup: () => removeDir(dir),
      };
    },
  },
  {
    name: 's3',
    enabled: process.env.S3_TEST === '1',
    make: () => ({
      env: {
        ...baseEnv,
        STORAGE_DRIVER: 's3',
        // Local compose MinIO (dev-only credentials from apps/api/.env.example).
        S3_ENDPOINT: process.env.S3_TEST_ENDPOINT ?? 'http://localhost:59000',
        S3_BUCKET: process.env.S3_TEST_BUCKET ?? 'cipherdrop-contract-test',
        S3_ACCESS_KEY_ID: process.env.S3_TEST_ACCESS_KEY_ID ?? 'cipherdrop',
        S3_SECRET_ACCESS_KEY: process.env.S3_TEST_SECRET_ACCESS_KEY ?? 'cipherdrop-dev-secret',
      },
      cleanup: async () => {},
    }),
  },
];

for (const c of cases) {
  describe.skipIf(!c.enabled)(`storage contract: ${c.name}`, () => {
    let storage: StorageDriver;
    let cleanup: () => Promise<void>;

    beforeAll(async () => {
      const made = c.make();
      cleanup = made.cleanup;
      storage = createStorage(made.env);
      await storage.init();
      // init() is idempotent (an existing bucket / directory is fine).
      await storage.init();
    });

    afterAll(async () => {
      await cleanup();
    });

    it('healthCheck resolves', async () => {
      await expect(storage.healthCheck()).resolves.toBeUndefined();
    });

    it('put/get roundtrip returns the exact bytes', async () => {
      const dropId = id16();
      const fileId = id16();
      const data = randomBytes(70_000);
      await storage.putChunk(dropId, fileId, 0, data);
      const got = await readAll(await storage.getChunkStream(dropId, fileId, 0));
      expect(got.equals(data)).toBe(true);
      await storage.deleteDrop(dropId);
    });

    it('stores the chunk of an empty file (16 bytes: tag only)', async () => {
      const dropId = id16();
      const fileId = id16();
      const tagOnly = randomBytes(16);
      await storage.putChunk(dropId, fileId, 0, tagOnly);
      expect((await readAll(await storage.getChunkStream(dropId, fileId, 0))).equals(tagOnly)).toBe(
        true,
      );
      await storage.deleteDrop(dropId);
    });

    it('overwrite replaces the chunk (idempotent re-PUT)', async () => {
      const dropId = id16();
      const fileId = id16();
      await storage.putChunk(dropId, fileId, 3, randomBytes(1000));
      const second = randomBytes(1200);
      await storage.putChunk(dropId, fileId, 3, second);
      const got = await readAll(await storage.getChunkStream(dropId, fileId, 3));
      expect(got.equals(second)).toBe(true);
      await storage.deleteDrop(dropId);
    });

    it('missing chunk rejects with NOT_FOUND', async () => {
      const dropId = id16();
      const fileId = id16();
      await expectNotFound(storage.getChunkStream(dropId, fileId, 0));
      await storage.putChunk(dropId, fileId, 0, randomBytes(10));
      await expectNotFound(storage.getChunkStream(dropId, fileId, 1));
      await expectNotFound(storage.getChunkStream(dropId, id16(), 0));
      await storage.deleteDrop(dropId);
    });

    it('deleteDrop removes every chunk of the drop (DeleteObjects for s3) and only that drop', async () => {
      const dropId = id16();
      const other = id16();
      const files = [id16(), id16()];
      for (const f of files) {
        for (let i = 0; i < 3; i++) await storage.putChunk(dropId, f, i, randomBytes(64));
      }
      await storage.putChunk(other, files[0] as string, 0, randomBytes(64));

      await storage.deleteDrop(dropId);
      for (const f of files) {
        for (let i = 0; i < 3; i++) await expectNotFound(storage.getChunkStream(dropId, f, i));
      }
      // Other drops are untouched.
      expect(
        (await readAll(await storage.getChunkStream(other, files[0] as string, 0))).length,
      ).toBe(64);
      // Idempotent: deleting again (or deleting an unknown drop) resolves.
      await expect(storage.deleteDrop(dropId)).resolves.toBeUndefined();
      await expect(storage.deleteDrop(id16())).resolves.toBeUndefined();
      await storage.deleteDrop(other);
    });

    it('deleteDrop handles more than one listing page', async () => {
      if (c.name !== 's3') return;
      const dropId = id16();
      const fileId = id16();
      // 1005 objects: more than one DeleteObjects batch (1000 keys max).
      const tiny = Buffer.from([1]);
      const all = Array.from({ length: 1005 }, (_, i) => i);
      for (let i = 0; i < all.length; i += 50) {
        await Promise.all(
          all.slice(i, i + 50).map((n) => storage.putChunk(dropId, fileId, n, tiny)),
        );
      }
      await storage.deleteDrop(dropId);
      await expectNotFound(storage.getChunkStream(dropId, fileId, 0));
      await expectNotFound(storage.getChunkStream(dropId, fileId, 1004));
    }, 120_000);

    it('rejects ids that could escape the storage namespace', async () => {
      const fileId = id16();
      for (const bad of ['..', '../x', 'a/b', 'a\\b', '', 'x'.repeat(100)]) {
        await expect(storage.putChunk(bad, fileId, 0, randomBytes(4))).rejects.toThrow();
        await expect(storage.putChunk(id16(), bad, 0, randomBytes(4))).rejects.toThrow();
      }
      await expect(storage.putChunk(id16(), fileId, -1, randomBytes(4))).rejects.toThrow();
      await expect(storage.putChunk(id16(), fileId, 1.5, randomBytes(4))).rejects.toThrow();
      await expect(storage.deleteDrop('..')).rejects.toThrow();
    });
  });
}
