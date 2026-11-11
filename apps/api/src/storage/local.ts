/**
 * Local filesystem blob driver (spec section 9, R21). Layout: <root>/<dropId>/<fileId>/<index>.
 *
 * - Writes are atomic: the chunk goes to a unique temp file in the same directory, then rename() replaces
 *   the target, so a reader sees either the old or the new chunk, never a partial one.
 * - Windows: rename is retried on EPERM/EACCES/EBUSY (antivirus or an open reader can hold the target
 *   briefly); directories are removed with fs.rm({recursive, force, maxRetries: 5}).
 * - The root is realpath'd at init (os.tmpdir() is an 8.3 short path on Windows) before the traversal guard
 *   compares resolved paths against it. Ids are additionally restricted to base64url characters.
 */
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Readable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import { notFound } from '../lib/errors';

import { assertBlobAddress, assertDropId, type StorageDriver } from './index';

const RETRY_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);
const RENAME_ATTEMPTS = 6;

const errCode = (err: unknown): string | undefined => (err as { code?: string } | null)?.code;

async function renameWithRetry(from: string, to: string): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await fs.promises.rename(from, to);
      return;
    } catch (err) {
      if (attempt >= RENAME_ATTEMPTS || !RETRY_CODES.has(errCode(err) ?? '')) throw err;
      await sleep(10 * 2 ** (attempt - 1));
    }
  }
}

export function createLocalStorage(storageDir: string): StorageDriver {
  const configured = path.resolve(storageDir);
  let rootPromise: Promise<string> | undefined;

  const root = (): Promise<string> => {
    rootPromise ??= (async () => {
      await fs.promises.mkdir(configured, { recursive: true });
      return fs.promises.realpath(configured);
    })();
    rootPromise.catch(() => {
      rootPromise = undefined;
    });
    return rootPromise;
  };

  /** Resolve a path under the root, refusing anything that would escape it. */
  const inside = async (...parts: string[]): Promise<string> => {
    const base = await root();
    const full = path.resolve(base, ...parts);
    if (full === base || !full.startsWith(base + path.sep)) {
      throw new Error('storage path escapes the storage root');
    }
    return full;
  };

  const chunkPath = async (dropId: string, fileId: string, index: number) => {
    assertBlobAddress(dropId, fileId, index);
    return inside(dropId, fileId, String(index));
  };

  return {
    async init() {
      await root();
    },

    async putChunk(dropId, fileId, index, data) {
      const target = await chunkPath(dropId, fileId, index);
      const dir = path.dirname(target);
      await fs.promises.mkdir(dir, { recursive: true });
      const temp = path.join(dir, `.${index}.${randomBytes(6).toString('hex')}.tmp`);
      try {
        await fs.promises.writeFile(temp, data, { flag: 'wx' });
        await renameWithRetry(temp, target);
      } catch (err) {
        await fs.promises.rm(temp, { force: true, maxRetries: 5 }).catch(() => {});
        throw err;
      }
    },

    async getChunkStream(dropId, fileId, index): Promise<Readable> {
      const file = await chunkPath(dropId, fileId, index);
      let handle: fs.promises.FileHandle;
      try {
        handle = await fs.promises.open(file, 'r');
      } catch (err) {
        if (errCode(err) === 'ENOENT' || errCode(err) === 'ENOTDIR')
          throw notFound('Unknown chunk');
        throw err;
      }
      return handle.createReadStream({ autoClose: true });
    },

    async deleteDrop(dropId) {
      assertDropId(dropId);
      const dir = await inside(dropId);
      await fs.promises.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },

    async healthCheck() {
      // Not the memoised root: a root deleted after init must fail the readiness probe.
      const real = await fs.promises.realpath(configured);
      await fs.promises.access(real, fs.constants.R_OK | fs.constants.W_OK);
    },
  };
}
