/**
 * The S3 driver against REAL versioned buckets (critic-4; S3_TEST=1, the compose MinIO, or MinIO in CI): on a
 * versioned bucket a plain delete only adds a delete marker, so the driver refuses to start there unless
 * S3_DELETE_ALL_VERSIONS is set, and then leaves no version and no marker behind. A bucket with Object Lock is
 * refused either way. The unit tests with a fake client are s3.test.ts.
 */
import { randomBytes } from 'node:crypto';
import { DeleteObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createVersionedBucket,
  listAllVersions,
  rawS3Client,
  S3_TEST,
  testS3Env,
} from '../../test/s3';
import { createStorage, type StorageDriver } from './index';

const id16 = () => randomBytes(16).toString('base64url');

describe.skipIf(!S3_TEST)('s3 driver on a versioned bucket', () => {
  const env = testS3Env('-versioned');
  const Bucket = env.S3_BUCKET;
  let raw: S3Client;
  let storage: StorageDriver;
  const drops: string[] = [];

  beforeAll(async () => {
    raw = rawS3Client(env);
    await createVersionedBucket(raw, Bucket);
    storage = createStorage({ ...env, S3_DELETE_ALL_VERSIONS: true });
    await storage.init();
  });

  afterAll(async () => {
    for (const d of drops) await storage.deleteDrop(d);
    raw.destroy();
  });

  it('refuses to start without S3_DELETE_ALL_VERSIONS: a delete there would keep every version', async () => {
    await expect(createStorage(env).init()).rejects.toThrow(
      /versioning is Enabled, so a delete would only add a delete marker/,
    );
    // Which is what a plain delete does on this bucket: the version stays, under a new delete marker.
    const Key = `drops/${id16()}/probe`;
    await raw.send(new PutObjectCommand({ Bucket, Key, Body: Buffer.from('ciphertext') }));
    await raw.send(new DeleteObjectCommand({ Bucket, Key }));
    const left = await listAllVersions(raw, Bucket, Key);
    expect(left).toHaveLength(2);
    expect(left.filter((v) => v.endsWith('(marker)'))).toHaveLength(1);
    drops.push(Key.split('/')[1] as string);
  });

  it('with S3_DELETE_ALL_VERSIONS, deleteChunk and deleteDrop leave no version and no delete marker', async () => {
    const dropId = id16();
    const other = id16();
    const fileId = id16();
    drops.push(dropId, other);
    const [v1, v2] = [id16(), id16()];
    // Two versions of one key (a re-PUT), two chunk versions, and another drop that must stay.
    await storage.putChunk(dropId, fileId, 0, randomBytes(100));
    await storage.putChunk(dropId, fileId, 0, randomBytes(100));
    await storage.putChunk(dropId, fileId, 1, randomBytes(100), v1);
    await storage.putChunk(dropId, fileId, 1, randomBytes(100), v2);
    await storage.putChunk(other, fileId, 0, randomBytes(100));
    // A delete marker as the old driver (or an operator's tool) would have left one, over a real version.
    const legacy = `drops/${dropId}/${fileId}/7`;
    await raw.send(new PutObjectCommand({ Bucket, Key: legacy, Body: Buffer.from('old') }));
    await raw.send(new DeleteObjectCommand({ Bucket, Key: legacy }));
    expect(await listAllVersions(raw, Bucket, `drops/${dropId}/`)).toHaveLength(6);

    await storage.deleteChunk(dropId, fileId, 1, v1);
    expect(await listAllVersions(raw, Bucket, `drops/${dropId}/${fileId}/1.${v1}`)).toEqual([]);
    expect(await listAllVersions(raw, Bucket, `drops/${dropId}/${fileId}/1.${v2}`)).toHaveLength(1);
    // The legacy key 0 is a prefix of nothing else here; deleting chunk 0 removes both of its versions.
    await storage.deleteChunk(dropId, fileId, 0);
    expect(await listAllVersions(raw, Bucket, `drops/${dropId}/${fileId}/0`)).toEqual([]);

    await storage.deleteDrop(dropId);
    expect(await listAllVersions(raw, Bucket, `drops/${dropId}/`)).toEqual([]);
    expect(await listAllVersions(raw, Bucket, `drops/${other}/`)).toHaveLength(1);
    // Idempotent.
    await expect(storage.deleteDrop(dropId)).resolves.toBeUndefined();
  });
});

describe.skipIf(!S3_TEST)('s3 driver on a bucket with Object Lock', () => {
  it('refuses to start, even with S3_DELETE_ALL_VERSIONS', async () => {
    const env = testS3Env('-locked');
    const raw = rawS3Client(env);
    try {
      await createVersionedBucket(raw, env.S3_BUCKET, true);
      for (const deleteAllVersions of [false, true]) {
        await expect(
          createStorage({ ...env, S3_DELETE_ALL_VERSIONS: deleteAllVersions }).init(),
        ).rejects.toThrow(/Object Lock is enabled/);
      }
    } finally {
      raw.destroy();
    }
  });
});
