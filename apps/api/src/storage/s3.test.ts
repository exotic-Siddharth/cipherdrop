/**
 * S3 driver against a fake client (critic-4): init() refuses a bucket where a delete would not be final (versioning
 * without S3_DELETE_ALL_VERSIONS, Object Lock, MFA Delete, settings it cannot read), and with S3_DELETE_ALL_VERSIONS
 * every delete removes each version and delete marker by its VersionId. The same behaviour against a real versioned
 * bucket is s3.versioning.test.ts (S3_TEST=1).
 */
import {
  CreateBucketCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetBucketVersioningCommand,
  GetObjectLockConfigurationCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  type ObjectIdentifier,
} from '@aws-sdk/client-s3';
import { describe, expect, it } from 'vitest';
import { createS3Storage, type S3Sender, type S3StorageEnv } from './s3';

const SECRET = 'fake-secret-access-key-never-printed';
const env = (deleteAllVersions = false): S3StorageEnv => ({
  S3_ENDPOINT: 'http://s3.test:9000',
  S3_REGION: 'us-east-1',
  S3_BUCKET: 'drops-bucket',
  S3_ACCESS_KEY_ID: 'fake-key-id',
  S3_SECRET_ACCESS_KEY: SECRET,
  S3_FORCE_PATH_STYLE: true,
  S3_DELETE_ALL_VERSIONS: deleteAllVersions,
});

type CommandClass = abstract new (...args: never[]) => { input: unknown };
type Handler = (input: Record<string, unknown>) => unknown;
interface Call {
  command: string;
  input: Record<string, unknown>;
}

const COMMANDS: [string, CommandClass][] = [
  ['CreateBucket', CreateBucketCommand],
  ['GetObjectLockConfiguration', GetObjectLockConfigurationCommand],
  ['GetBucketVersioning', GetBucketVersioningCommand],
  ['ListObjectsV2', ListObjectsV2Command],
  ['ListObjectVersions', ListObjectVersionsCommand],
  ['DeleteObjects', DeleteObjectsCommand],
  ['DeleteObject', DeleteObjectCommand],
];

/** A client whose send() answers each command with its handler, and records every call. */
function fakeS3(handlers: Record<string, Handler>): { client: S3Sender; calls: Call[] } {
  const calls: Call[] = [];
  const client = {
    async send(command: { input: unknown }) {
      const name = COMMANDS.find(([, C]) => command instanceof C)?.[0] ?? 'unknown';
      const input = command.input as Record<string, unknown>;
      calls.push({ command: name, input });
      const handler = handlers[name];
      if (!handler) throw new Error(`unexpected command ${name}`);
      return handler(input);
    },
  };
  return { client: client as unknown as S3Sender, calls };
}

/** An error shaped like the SDK's service exceptions (name + HTTP status). */
const s3Error = (name: string, status: number) =>
  Object.assign(new Error(`${name} from the fake server`), {
    name,
    $metadata: { httpStatusCode: status },
  });
const fail = (name: string, status: number) => () => {
  throw s3Error(name, status);
};

/** The bucket-settings handlers of a bucket: its versioning answer and its Object Lock answer. */
function bucket(
  versioning: Handler,
  lock: Handler = fail('ObjectLockConfigurationNotFoundError', 404),
) {
  return {
    CreateBucket: fail('BucketAlreadyOwnedByYou', 409),
    GetObjectLockConfiguration: lock,
    GetBucketVersioning: versioning,
  };
}

async function initError(
  handlers: Record<string, Handler>,
  deleteAllVersions = false,
): Promise<string | null> {
  const { client } = fakeS3(handlers);
  return createS3Storage(env(deleteAllVersions), { client })
    .init()
    .then(
      () => null,
      (err: unknown) => (err as Error).message,
    );
}

describe('s3 driver init(): a delete must be final', () => {
  it('accepts an unversioned bucket without Object Lock, after creating it', async () => {
    const { client, calls } = fakeS3(bucket(() => ({})));
    await expect(createS3Storage(env(), { client }).init()).resolves.toBeUndefined();
    expect(calls.map((c) => c.command)).toEqual([
      'CreateBucket',
      'GetObjectLockConfiguration',
      'GetBucketVersioning',
    ]);
    expect(calls.every((c) => c.input.Bucket === 'drops-bucket')).toBe(true);
  });

  it.each(['Enabled', 'Suspended'])(
    'refuses a bucket whose versioning is %s unless S3_DELETE_ALL_VERSIONS is set',
    async (Status) => {
      const message = await initError(bucket(() => ({ Status })));
      expect(message).toContain('S3 bucket "drops-bucket"');
      expect(message).toContain(`versioning is ${Status}`);
      expect(message).toContain('delete marker');
      expect(message).toContain('S3_DELETE_ALL_VERSIONS=true');
      expect(message).not.toContain(SECRET);
      await expect(
        initError(
          bucket(() => ({ Status })),
          true,
        ),
      ).resolves.toBeNull();
    },
  );

  it('refuses a bucket with Object Lock, even with S3_DELETE_ALL_VERSIONS', async () => {
    const locked = bucket(
      () => ({ Status: 'Enabled' }),
      () => ({ ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } }),
    );
    for (const deleteAllVersions of [false, true]) {
      const message = await initError(locked, deleteAllVersions);
      expect(message).toContain('Object Lock is enabled');
      expect(message).not.toContain(SECRET);
    }
    // A configuration without ObjectLockEnabled is no lock.
    await expect(
      initError(
        bucket(
          () => ({}),
          () => ({ ObjectLockConfiguration: {} }),
        ),
      ),
    ).resolves.toBeNull();
  });

  it('refuses versioning with MFA Delete, even with S3_DELETE_ALL_VERSIONS (a version delete needs MFA)', async () => {
    const mfa = bucket(() => ({ Status: 'Enabled', MFADelete: 'Enabled' }));
    expect(await initError(mfa, true)).toContain('MFA Delete');
    // MFADelete without versioning does not matter.
    await expect(initError(bucket(() => ({ MFADelete: 'Disabled' })))).resolves.toBeNull();
  });

  it('takes NotImplemented (servers without the feature, such as R2) as "not enabled"', async () => {
    await expect(
      initError(bucket(fail('NotImplemented', 501), fail('NotImplemented', 501))),
    ).resolves.toBeNull();
    await expect(
      initError(bucket(fail('SomethingElse', 501), fail('SomethingElse', 501))),
    ).resolves.toBeNull();
  });

  it('fails closed when it cannot read the versioning state, unless every version is deleted anyway', async () => {
    const denied = bucket(fail('AccessDenied', 403));
    const message = await initError(denied);
    expect(message).toContain('cannot read its versioning state (AccessDenied)');
    expect(message).toContain('s3:GetBucketVersioning');
    await expect(initError(denied, true)).resolves.toBeNull();
  });

  it('fails closed when it cannot read the Object Lock configuration, with or without S3_DELETE_ALL_VERSIONS', async () => {
    const denied = bucket(() => ({}), fail('AccessDenied', 403));
    for (const deleteAllVersions of [false, true]) {
      const message = await initError(denied, deleteAllVersions);
      expect(message).toContain('cannot read its Object Lock configuration (AccessDenied)');
      expect(message).toContain('s3:GetBucketObjectLockConfiguration');
    }
  });

  it('still fails on a CreateBucket error other than "already exists"', async () => {
    const message = await initError({
      ...bucket(() => ({})),
      CreateBucket: fail('AccessDenied', 403),
    });
    expect(message).toContain('AccessDenied');
  });
});

/** A ListObjectVersions answer: versions and delete markers of the given keys. */
const versionsPage = (
  versions: [string, string][],
  markers: [string, string][] = [],
  next?: { key: string; version: string },
) => ({
  Versions: versions.map(([Key, VersionId]) => ({ Key, VersionId })),
  DeleteMarkers: markers.map(([Key, VersionId]) => ({ Key, VersionId })),
  IsTruncated: next !== undefined,
  NextKeyMarker: next?.key,
  NextVersionIdMarker: next?.version,
});

const deleted = (calls: Call[]): ObjectIdentifier[] =>
  calls
    .filter((c) => c.command === 'DeleteObjects')
    .flatMap((c) => (c.input.Delete as { Objects: ObjectIdentifier[] }).Objects);

const DROP = 'AAAAAAAAAAAAAAAAAAAAAA';
const FILE = 'BBBBBBBBBBBBBBBBBBBBBB';
const key = (leaf: string) => `drops/${DROP}/${FILE}/${leaf}`;

describe('s3 driver deletes with S3_DELETE_ALL_VERSIONS', () => {
  it('deleteDrop deletes every version and delete marker by VersionId, page by page, until nothing is left', async () => {
    let listed = 0;
    const { client, calls } = fakeS3({
      ListObjectVersions: (input) => {
        listed++;
        if (listed === 1) {
          return versionsPage(
            [
              [key('0.v1'), 'a1'],
              [key('0.v1'), 'a2'],
            ],
            [[key('0.v1'), 'm1']],
            { key: key('0.v1'), version: 'a2' },
          );
        }
        if (listed === 2) {
          expect(input).toMatchObject({ KeyMarker: key('0.v1'), VersionIdMarker: 'a2' });
          return versionsPage([[key('1.v2'), 'b1']]);
        }
        return versionsPage([]); // the second pass finds nothing left
      },
      DeleteObjects: () => ({}),
    });
    await createS3Storage(env(true), { client }).deleteDrop(DROP);

    expect(deleted(calls)).toEqual([
      { Key: key('0.v1'), VersionId: 'a1' },
      { Key: key('0.v1'), VersionId: 'a2' },
      { Key: key('0.v1'), VersionId: 'm1' },
      { Key: key('1.v2'), VersionId: 'b1' },
    ]);
    const lists = calls.filter((c) => c.command === 'ListObjectVersions');
    expect(lists).toHaveLength(3);
    expect(lists.every((c) => c.input.Prefix === `drops/${DROP}/`)).toBe(true);
    expect(lists[2]?.input.KeyMarker).toBeUndefined();
    expect(calls.some((c) => c.command === 'ListObjectsV2')).toBe(false);
  });

  it('sends at most 1000 versions per DeleteObjects', async () => {
    let listed = 0;
    const many = Array.from({ length: 1500 }, (_, i): [string, string] => [
      key(String(i)),
      `v${i}`,
    ]);
    const { client, calls } = fakeS3({
      ListObjectVersions: () => versionsPage(listed++ === 0 ? many : []),
      DeleteObjects: () => ({}),
    });
    await createS3Storage(env(true), { client }).deleteDrop(DROP);
    const batches = calls
      .filter((c) => c.command === 'DeleteObjects')
      .map((c) => (c.input.Delete as { Objects: unknown[] }).Objects.length);
    expect(batches).toEqual([1000, 500]);
  });

  it('fails when the server reports a version it did not delete, and when versions keep reappearing', async () => {
    const refused = fakeS3({
      ListObjectVersions: () => versionsPage([[key('0'), 'a1']]),
      DeleteObjects: () => ({ Errors: [{ Key: key('0'), VersionId: 'a1', Code: 'AccessDenied' }] }),
    });
    await expect(createS3Storage(env(true), refused).deleteDrop(DROP)).rejects.toThrow(
      /DeleteObjects failed for 1 object/,
    );
    const endless = fakeS3({
      ListObjectVersions: () => versionsPage([[key('0'), 'a1']]),
      DeleteObjects: () => ({}),
    });
    await expect(createS3Storage(env(true), endless).deleteDrop(DROP)).rejects.toThrow(
      /remain after 5 passes/,
    );
  });

  it('deleteChunk deletes every version of exactly that key, not of keys it is a prefix of', async () => {
    const { client, calls } = fakeS3({
      ListObjectVersions: () =>
        versionsPage(
          [
            [key('1'), 'x1'],
            [key('1'), 'x2'],
            [key('1.v9'), 'y1'],
            [key('10'), 'z1'],
          ],
          [[key('1'), 'm1']],
        ),
      DeleteObjects: () => ({}),
    });
    await createS3Storage(env(true), { client }).deleteChunk(DROP, FILE, 1);
    expect(calls.find((c) => c.command === 'ListObjectVersions')?.input.Prefix).toBe(key('1'));
    expect(deleted(calls)).toEqual([
      { Key: key('1'), VersionId: 'x1' },
      { Key: key('1'), VersionId: 'x2' },
      { Key: key('1'), VersionId: 'm1' },
    ]);
    expect(calls.some((c) => c.command === 'DeleteObject')).toBe(false);
  });
});

describe('s3 driver deletes without S3_DELETE_ALL_VERSIONS (an unversioned bucket, checked at init)', () => {
  it('deleteDrop lists keys and deletes them without a VersionId; deleteChunk is one DeleteObject', async () => {
    const { client, calls } = fakeS3({
      ListObjectsV2: () => ({
        Contents: [{ Key: key('0') }, { Key: key('1') }],
        IsTruncated: false,
      }),
      DeleteObjects: () => ({}),
      DeleteObject: () => ({}),
    });
    const storage = createS3Storage(env(), { client });
    await storage.deleteDrop(DROP);
    expect(deleted(calls)).toEqual([{ Key: key('0') }, { Key: key('1') }]);
    await storage.deleteChunk(DROP, FILE, 3, 'v3');
    expect(calls.at(-1)).toEqual({
      command: 'DeleteObject',
      input: { Bucket: 'drops-bucket', Key: key('3.v3') },
    });
    expect(calls.some((c) => c.command === 'ListObjectVersions')).toBe(false);
  });
});
