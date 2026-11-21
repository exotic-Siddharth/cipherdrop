/**
 * S3 test helpers (S3_TEST=1 only): the compose MinIO on 59000 by default (dev-only credentials from
 * apps/api/.env.example), or S3_TEST_ENDPOINT / S3_TEST_BUCKET / S3_TEST_ACCESS_KEY_ID / S3_TEST_SECRET_ACCESS_KEY.
 */
import {
  CreateBucketCommand,
  ListObjectVersionsCommand,
  PutBucketVersioningCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import type { StorageEnv } from '../src/storage/index';

export const S3_TEST = process.env.S3_TEST === '1';

/** Storage env of the S3 driver against the test server; `bucketSuffix` names a bucket of its own. */
export function testS3Env(bucketSuffix = '', overrides: Partial<StorageEnv> = {}): StorageEnv {
  return {
    STORAGE_DRIVER: 's3',
    STORAGE_DIR: '',
    S3_ENDPOINT: process.env.S3_TEST_ENDPOINT ?? 'http://localhost:59000',
    S3_REGION: 'us-east-1',
    S3_BUCKET: `${process.env.S3_TEST_BUCKET ?? 'cipherdrop-contract-test'}${bucketSuffix}`,
    S3_ACCESS_KEY_ID: process.env.S3_TEST_ACCESS_KEY_ID ?? 'cipherdrop',
    S3_SECRET_ACCESS_KEY: process.env.S3_TEST_SECRET_ACCESS_KEY ?? 'cipherdrop-dev-secret',
    S3_FORCE_PATH_STYLE: true,
    S3_DELETE_ALL_VERSIONS: false,
    ...overrides,
  };
}

/** A plain client for the test server, to set buckets up and inspect them behind the driver's back. */
export function rawS3Client(env: StorageEnv = testS3Env()): S3Client {
  return new S3Client({
    region: env.S3_REGION,
    endpoint: env.S3_ENDPOINT,
    forcePathStyle: true,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    credentials: {
      accessKeyId: env.S3_ACCESS_KEY_ID as string,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY as string,
    },
  });
}

/** Create `bucket` if missing (with Object Lock when asked, which implies versioning) and enable versioning. */
export async function createVersionedBucket(
  client: S3Client,
  bucket: string,
  objectLock = false,
): Promise<void> {
  try {
    await client.send(
      new CreateBucketCommand({ Bucket: bucket, ObjectLockEnabledForBucket: objectLock }),
    );
  } catch (err) {
    const name = (err as { name?: string }).name ?? '';
    if (!['BucketAlreadyOwnedByYou', 'BucketAlreadyExists'].includes(name)) throw err;
  }
  await client.send(
    new PutBucketVersioningCommand({
      Bucket: bucket,
      VersioningConfiguration: { Status: 'Enabled' },
    }),
  );
}

/** Every version and every delete marker under `prefix`, as "key@versionId" (markers end in " (marker)"). */
export async function listAllVersions(
  client: S3Client,
  bucket: string,
  prefix: string,
): Promise<string[]> {
  const out: string[] = [];
  let KeyMarker: string | undefined;
  let VersionIdMarker: string | undefined;
  for (;;) {
    const page = await client.send(
      new ListObjectVersionsCommand({ Bucket: bucket, Prefix: prefix, KeyMarker, VersionIdMarker }),
    );
    for (const v of page.Versions ?? []) out.push(`${v.Key}@${v.VersionId}`);
    for (const m of page.DeleteMarkers ?? []) out.push(`${m.Key}@${m.VersionId} (marker)`);
    if (!page.IsTruncated) return out;
    KeyMarker = page.NextKeyMarker;
    VersionIdMarker = page.NextVersionIdMarker;
  }
}
