/**
 * S3 driver socket pool (S3_TEST=1, compose MinIO): chunk GET streams that nobody reads must not exhaust the
 * client's sockets and stall every other storage call (the default handler allows only 50).
 */
import { randomBytes } from 'node:crypto';
import type { Readable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createStorage, type StorageDriver, type StorageEnv } from './index';

const env: StorageEnv = {
  STORAGE_DRIVER: 's3',
  STORAGE_DIR: '',
  S3_ENDPOINT: process.env.S3_TEST_ENDPOINT ?? 'http://localhost:59000',
  S3_REGION: 'us-east-1',
  S3_BUCKET: process.env.S3_TEST_BUCKET ?? 'cipherdrop-contract-test',
  S3_ACCESS_KEY_ID: process.env.S3_TEST_ACCESS_KEY_ID ?? 'cipherdrop',
  S3_SECRET_ACCESS_KEY: process.env.S3_TEST_SECRET_ACCESS_KEY ?? 'cipherdrop-dev-secret',
  S3_FORCE_PATH_STYLE: true,
};

describe.skipIf(process.env.S3_TEST !== '1')('s3 driver socket pool', () => {
  let storage: StorageDriver;
  const dropId = randomBytes(16).toString('base64url');
  const fileId = randomBytes(16).toString('base64url');
  const open: Readable[] = [];

  beforeAll(async () => {
    storage = createStorage(env);
    await storage.init();
    await storage.putChunk(dropId, fileId, 0, randomBytes(4 * 1024 * 1024));
  });
  afterAll(async () => {
    for (const s of open) s.destroy();
    await storage.deleteDrop(dropId);
  });

  it('60 unread chunk streams do not block a write or a health check', async () => {
    for (let i = 0; i < 60; i++) open.push(await storage.getChunkStream(dropId, fileId, 0));
    const write = storage.putChunk(dropId, fileId, 1, randomBytes(1024)).then(() => 'done');
    const health = storage.healthCheck().then(() => 'done');
    const outcome = await Promise.race([
      Promise.all([write, health]).then(() => 'done' as const),
      sleep(8000).then(() => 'blocked' as const),
    ]);
    expect(outcome).toBe('done');
  }, 40_000);
});
