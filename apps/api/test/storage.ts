import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** A fresh temp directory for local blob storage (realpath'd: os.tmpdir() is an 8.3 short path on Windows, R21). */
export function tempStorageDir(prefix = 'cipherdrop-blobs-'): string {
  const base = fs.realpathSync.native(os.tmpdir());
  return fs.mkdtempSync(path.join(base, prefix));
}

/** Remove a directory tree, retrying transient Windows EBUSY/EPERM errors (R21). */
export async function removeDir(dir: string): Promise<void> {
  await fs.promises.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
