/**
 * S3-compatible blob driver (MinIO in dev, S3/R2 in prod; R17).
 * Keys: drops/<dropId>/<fileId>/<index>[.<version>].
 *
 * - forcePathStyle (MinIO), and requestChecksumCalculation/responseChecksumValidation WHEN_REQUIRED: newer
 *   SDKs otherwise add CRC32 trailers that some S3-compatible servers reject.
 * - init() creates the bucket, ignoring BucketAlreadyOwnedByYou / BucketAlreadyExists.
 * - deleteDrop lists the drop prefix and removes it with DeleteObjects in batches of up to 1000 keys.
 * - requestHandler: 256 sockets, 5 s connect timeout, 60 s idle-socket timeout (a stalled GetObject body is
 *   destroyed instead of pinning a socket).
 * - A PUT replaces the object atomically, so overwrites (idempotent re-PUT) need nothing special.
 */
import {
  CreateBucketCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadBucketCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
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

const errName = (err: unknown): string | undefined => (err as { name?: string } | null)?.name;
const httpStatus = (err: unknown): number | undefined =>
  (err as { $metadata?: { httpStatusCode?: number } } | null)?.$metadata?.httpStatusCode;

export type S3StorageEnv = Omit<StorageEnv, 'STORAGE_DRIVER' | 'STORAGE_DIR'>;

export function createS3Storage(storageEnv: S3StorageEnv): StorageDriver {
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
  const client = new S3Client(config);
  const Bucket = storageEnv.S3_BUCKET;

  const dropPrefix = (dropId: string) => `drops/${dropId}/`;
  const objectKey = (dropId: string, fileId: string, index: number, version?: string) => {
    assertBlobAddress(dropId, fileId, index, version);
    return `${dropPrefix(dropId)}${fileId}/${chunkLeaf(index, version)}`;
  };

  return {
    async init() {
      try {
        await client.send(new CreateBucketCommand({ Bucket }));
      } catch (err) {
        if (!IGNORED_CREATE_ERRORS.has(errName(err) ?? '')) throw err;
      }
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
      await client.send(
        new DeleteObjectCommand({ Bucket, Key: objectKey(dropId, fileId, index, version) }),
      );
    },

    async deleteDrop(dropId) {
      assertDropId(dropId);
      const Prefix = dropPrefix(dropId);
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
