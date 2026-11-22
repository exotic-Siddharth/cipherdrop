/**
 * S3-compatible blob driver (MinIO in dev, S3/R2 in prod; R17).
 * Keys: drops/<dropId>/<fileId>/<index>[.<version>].
 *
 * - forcePathStyle (MinIO), and requestChecksumCalculation/responseChecksumValidation WHEN_REQUIRED: newer
 *   SDKs otherwise add CRC32 trailers that some S3-compatible servers reject.
 * - init() creates the bucket, ignoring BucketAlreadyOwnedByYou / BucketAlreadyExists, and then refuses to start
 *   unless a delete is final (critic-4, below).
 * - deleteDrop lists the drop prefix and removes it with DeleteObjects in batches of up to 1000 keys.
 *
 * Versioned buckets. On a bucket with versioning enabled (or suspended after it was enabled), DeleteObject(s)
 * without a VersionId only adds a delete marker: every ciphertext version stays readable to whoever holds the
 * bucket, and expiry, burn after reading, "Delete now", admin disable and account deletion would all succeed
 * silently without deleting anything. So init() reads the bucket's settings and refuses to start:
 * - when Object Lock is enabled, always: a version under retention or legal hold cannot be deleted until it
 *   lapses (in compliance mode not even by the account root);
 * - when versioning is on, unless S3_DELETE_ALL_VERSIONS=true. Then every delete lists the versions and delete
 *   markers (ListObjectVersions) and deletes each by its VersionId, which removes it for good; that needs the
 *   s3:ListBucketVersions and s3:DeleteObjectVersion permissions. It works on an unversioned bucket too;
 * - when versioning is on with MFA Delete, always: a version delete would need an MFA code;
 * - when it cannot read a setting (AccessDenied and the like): fail closed. Without S3_DELETE_ALL_VERSIONS it
 *   needs s3:GetBucketVersioning; it always needs s3:GetBucketObjectLockConfiguration. A server that does not
 *   implement one of the two calls (NotImplemented, HTTP 501) has no such feature.
 * - requestHandler: 256 sockets, 5 s connect timeout, 60 s idle-socket timeout (a stalled GetObject body is
 *   destroyed instead of pinning a socket).
 * - A PUT replaces the object atomically, so overwrites (idempotent re-PUT) need nothing special.
 */
import {
  CreateBucketCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  HeadBucketCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
  type ObjectIdentifier,
  type S3ClientConfig,
} from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import { notFound } from '../lib/errors';
import {
  assertBlobAddress,
  assertDropId,
  chunkLeaf,
  type StorageDriver,
  type StorageEnv,
} from './index';

const S3_MAX_SOCKETS = 256;
const S3_CONNECT_TIMEOUT_MS = 5_000;
const S3_SOCKET_IDLE_TIMEOUT_MS = 60_000;

const IGNORED_CREATE_ERRORS = new Set(['BucketAlreadyOwnedByYou', 'BucketAlreadyExists']);
const NOT_FOUND_ERRORS = new Set(['NoSuchKey', 'NotFound']);
/** GetObjectLockConfiguration on a bucket that has no Object Lock (AWS, MinIO). */
const NO_LOCK_ERRORS = new Set(['ObjectLockConfigurationNotFoundError']);
/** DeleteObjects takes at most 1000 keys (or versions) per request. */
const DELETE_BATCH = 1000;
/** Passes over a prefix before deleteDrop gives up: each pass deletes what it lists, the last must find nothing. */
const MAX_VERSION_PASSES = 5;

const errName = (err: unknown): string | undefined => (err as { name?: string } | null)?.name;
const httpStatus = (err: unknown): number | undefined =>
  (err as { $metadata?: { httpStatusCode?: number } } | null)?.$metadata?.httpStatusCode;

/** A server without the feature (R2 and others answer NotImplemented to calls they do not support). */
const notImplemented = (err: unknown) =>
  errName(err) === 'NotImplemented' || httpStatus(err) === 501;

/** The error init() throws: names the setting and what to change, never a credential. */
const refuse = (bucket: string, why: string) =>
  new Error(`S3 bucket "${bucket}": ${why} (see docs/DEPLOYMENT.md, S3 storage)`);

export type S3StorageEnv = Omit<StorageEnv, 'STORAGE_DRIVER' | 'STORAGE_DIR'>;

/** What the driver needs of an S3Client (tests pass a fake). */
export type S3Sender = Pick<S3Client, 'send'>;

export function createS3Storage(
  storageEnv: S3StorageEnv,
  deps: { client?: S3Sender } = {},
): StorageDriver {
  const config: S3ClientConfig = {
    region: storageEnv.S3_REGION,
    forcePathStyle: storageEnv.S3_FORCE_PATH_STYLE,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    // The default handler allows 50 sockets and has no timeouts: 50 stalled chunk GETs would block every
    // other storage call. A bigger pool, a connect timeout, and an idle-socket timeout that also destroys a
    // response body stuck mid-stream (the route aborts stalled client reads too, CHUNK_IDLE_TIMEOUT_SEC).
    requestHandler: {
      connectionTimeout: S3_CONNECT_TIMEOUT_MS,
      socketTimeout: S3_SOCKET_IDLE_TIMEOUT_MS,
      httpAgent: { keepAlive: true, maxSockets: S3_MAX_SOCKETS },
      httpsAgent: { keepAlive: true, maxSockets: S3_MAX_SOCKETS },
    },
    ...(storageEnv.S3_ENDPOINT ? { endpoint: storageEnv.S3_ENDPOINT } : {}),
    ...(storageEnv.S3_ACCESS_KEY_ID && storageEnv.S3_SECRET_ACCESS_KEY
      ? {
          credentials: {
            accessKeyId: storageEnv.S3_ACCESS_KEY_ID,
            secretAccessKey: storageEnv.S3_SECRET_ACCESS_KEY,
          },
        }
      : {}),
  };
  const client = deps.client ?? new S3Client(config);
  const Bucket = storageEnv.S3_BUCKET;
  const deleteAllVersions = storageEnv.S3_DELETE_ALL_VERSIONS;

  const dropPrefix = (dropId: string) => `drops/${dropId}/`;
  const objectKey = (dropId: string, fileId: string, index: number, version?: string) => {
    assertBlobAddress(dropId, fileId, index, version);
    return `${dropPrefix(dropId)}${fileId}/${chunkLeaf(index, version)}`;
  };

  /** Refuses (throws) unless a delete in this bucket is final; see the header. */
  async function assertDeletesAreFinal(): Promise<void> {
    let lock: string | undefined;
    try {
      const out = await client.send(new GetObjectLockConfigurationCommand({ Bucket }));
      lock = out.ObjectLockConfiguration?.ObjectLockEnabled;
    } catch (err) {
      if (!NO_LOCK_ERRORS.has(errName(err) ?? '') && !notImplemented(err)) {
        throw refuse(
          Bucket,
          `cannot read its Object Lock configuration (${errName(err) ?? 'error'}); grant s3:GetBucketObjectLockConfiguration`,
        );
      }
    }
    if (lock === 'Enabled') {
      throw refuse(
        Bucket,
        'Object Lock is enabled, so deleted drops would stay stored until their retention ends; use a bucket without Object Lock',
      );
    }

    let status: string | undefined;
    let mfaDelete: string | undefined;
    try {
      const out = await client.send(new GetBucketVersioningCommand({ Bucket }));
      status = out.Status;
      mfaDelete = out.MFADelete;
    } catch (err) {
      // With S3_DELETE_ALL_VERSIONS every delete removes each version anyway, whatever the bucket's setting.
      if (!notImplemented(err) && !deleteAllVersions) {
        throw refuse(
          Bucket,
          `cannot read its versioning state (${errName(err) ?? 'error'}); grant s3:GetBucketVersioning, or set S3_DELETE_ALL_VERSIONS=true`,
        );
      }
    }
    // Suspended still keeps every version written while versioning was enabled.
    const versioned = status === 'Enabled' || status === 'Suspended';
    if (versioned && mfaDelete === 'Enabled') {
      throw refuse(Bucket, 'versioning has MFA Delete enabled, so old versions cannot be deleted');
    }
    if (versioned && !deleteAllVersions) {
      throw refuse(
        Bucket,
        `versioning is ${status}, so a delete would only add a delete marker and keep every ciphertext version; use an unversioned bucket, or set S3_DELETE_ALL_VERSIONS=true to delete every version`,
      );
    }
  }

  /**
   * Every version and delete marker under `Prefix` (only those of exactly `key` when given), page by page.
   * Deleting the entries of a page does not move the markers of the next one.
   */
  async function* versionPages(Prefix: string, key?: string): AsyncGenerator<ObjectIdentifier[]> {
    let KeyMarker: string | undefined;
    let VersionIdMarker: string | undefined;
    for (;;) {
      const page = await client.send(
        new ListObjectVersionsCommand({
          Bucket,
          Prefix,
          KeyMarker,
          VersionIdMarker,
          MaxKeys: 1000,
        }),
      );
      yield [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]
        .filter((v) => typeof v.Key === 'string' && (key === undefined || v.Key === key))
        .map((v) => ({ Key: v.Key as string, VersionId: v.VersionId }));
      if (!page.IsTruncated) return;
      KeyMarker = page.NextKeyMarker;
      VersionIdMarker = page.NextVersionIdMarker;
    }
  }

  /** DeleteObjects in batches; an object the server reports as not deleted fails the whole call. */
  async function deleteObjects(objects: ObjectIdentifier[]): Promise<void> {
    for (let i = 0; i < objects.length; i += DELETE_BATCH) {
      const res = await client.send(
        new DeleteObjectsCommand({
          Bucket,
          Delete: { Objects: objects.slice(i, i + DELETE_BATCH), Quiet: true },
        }),
      );
      if (res.Errors && res.Errors.length > 0) {
        throw new Error(`DeleteObjects failed for ${res.Errors.length} object(s)`);
      }
    }
  }

  /** Delete every version and delete marker under `Prefix` (of exactly `key` when given); the count deleted. */
  async function deleteVersions(Prefix: string, key?: string): Promise<number> {
    let deleted = 0;
    for await (const entries of versionPages(Prefix, key)) {
      await deleteObjects(entries);
      deleted += entries.length;
    }
    return deleted;
  }

  return {
    async init() {
      try {
        await client.send(new CreateBucketCommand({ Bucket }));
      } catch (err) {
        if (!IGNORED_CREATE_ERRORS.has(errName(err) ?? '')) throw err;
      }
      await assertDeletesAreFinal();
    },

    async putChunk(dropId, fileId, index, data, version) {
      await client.send(
        new PutObjectCommand({
          Bucket,
          Key: objectKey(dropId, fileId, index, version),
          Body: data,
          ContentLength: data.length,
          ContentType: 'application/octet-stream',
        }),
      );
    },

    async getChunkStream(dropId, fileId, index, version) {
      const Key = objectKey(dropId, fileId, index, version);
      try {
        const out = await client.send(new GetObjectCommand({ Bucket, Key }));
        const body = out.Body;
        if (body instanceof Readable) return body;
        if (
          body &&
          typeof (body as { transformToByteArray?: unknown }).transformToByteArray === 'function'
        ) {
          const bytes = await (
            body as { transformToByteArray(): Promise<Uint8Array> }
          ).transformToByteArray();
          return Readable.from([Buffer.from(bytes)]);
        }
        return Readable.from([]);
      } catch (err) {
        if (NOT_FOUND_ERRORS.has(errName(err) ?? '') || httpStatus(err) === 404) {
          throw notFound('Unknown chunk');
        }
        throw err;
      }
    },

    async deleteChunk(dropId, fileId, index, version) {
      const Key = objectKey(dropId, fileId, index, version);
      if (deleteAllVersions) {
        await deleteVersions(Key, Key);
        return;
      }
      await client.send(new DeleteObjectCommand({ Bucket, Key }));
    },

    async deleteDrop(dropId) {
      assertDropId(dropId);
      const Prefix = dropPrefix(dropId);
      if (deleteAllVersions) {
        // Until a pass finds nothing left: a chunk PUT racing the purge may add a version behind the listing.
        for (let pass = 0; pass < MAX_VERSION_PASSES; pass++) {
          if ((await deleteVersions(Prefix)) === 0) return;
        }
        throw new Error(`versions under a drop prefix remain after ${MAX_VERSION_PASSES} passes`);
      }
      // Delete page by page; each listing returns at most 1000 keys, the DeleteObjects maximum.
      for (;;) {
        const page = await client.send(new ListObjectsV2Command({ Bucket, Prefix, MaxKeys: 1000 }));
        const keys = (page.Contents ?? [])
          .map((o) => o.Key)
          .filter((k): k is string => typeof k === 'string');
        if (keys.length === 0) return;
        const res = await client.send(
          new DeleteObjectsCommand({
            Bucket,
            Delete: { Objects: keys.map((Key) => ({ Key })), Quiet: true },
          }),
        );
        if (res.Errors && res.Errors.length > 0) {
          throw new Error(`DeleteObjects failed for ${res.Errors.length} object(s)`);
        }
        if (!page.IsTruncated && keys.length < 1000) return;
      }
    },

    async healthCheck() {
      await client.send(new HeadBucketCommand({ Bucket }));
    },
  };
}
