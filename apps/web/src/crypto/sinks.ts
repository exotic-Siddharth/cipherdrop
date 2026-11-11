/**
 * Where decrypted bytes go (spec 11.2/11.3, R22).
 *
 * - Files of BLOB_SAVE_MAX_BYTES (256 MiB) or less: an in-memory Blob, saved with <a download> (lib/files)
 *   and reused for previews.
 * - Larger files: a FileSystemWritableFileStream from showSaveFilePicker, which must be called FIRST inside
 *   the click handler (it needs transient user activation), before any await.
 *
 * A sink only materialises a file on close(). abort() discards everything written so far: the Blob parts are
 * dropped, and a FileSystemWritableFileStream abort leaves the target untouched (Chromium writes to a
 * temporary swap file until close). So a stream that fails authentication never yields a saved file.
 */
import { LIMITS } from '@cipherdrop/shared';

export interface FileSink {
  readonly kind: 'blob' | 'file-system';
  write(chunk: Uint8Array): Promise<void>;
  /** Finish the file: the Blob for a Blob sink, null for a file-system sink. */
  close(): Promise<Blob | null>;
  /** Discard the partial file. Safe to call more than once and after close. */
  abort(): Promise<void>;
}

/** Simple `type/subtype` MIME (no parameters); anything else is saved as application/octet-stream. */
const SAFE_MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/i;

export function safeBlobType(type: string | null | undefined): string {
  return type && SAFE_MIME_RE.test(type) ? type.toLowerCase() : 'application/octet-stream';
}

/** True when the file is too large for an in-memory Blob and needs the save picker (R22). */
export function needsSavePicker(plaintextBytes: number): boolean {
  return plaintextBytes > LIMITS.BLOB_SAVE_MAX_BYTES;
}

export function createBlobSink(type: string): FileSink {
  let parts: Uint8Array<ArrayBuffer>[] = [];
  let state: 'open' | 'closed' | 'aborted' = 'open';
  return {
    kind: 'blob',
    async write(chunk) {
      if (state !== 'open') throw new Error(`write after ${state}`);
      // Copy: the caller's buffer may be reused, and BlobPart needs an ArrayBuffer-backed view.
      parts.push(new Uint8Array(chunk));
    },
    async close() {
      if (state !== 'open') throw new Error(`close after ${state}`);
      state = 'closed';
      const blob = new Blob(parts, { type: safeBlobType(type) });
      parts = [];
      return blob;
    },
    async abort() {
      if (state === 'open') state = 'aborted';
      parts = [];
    },
  };
}

/* ---- File System Access API (not in TypeScript's DOM lib yet; Chromium only) ---- */

export interface WritableFileStreamLike {
  write(data: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

export interface SaveFileHandleLike {
  readonly name?: string;
  createWritable(options?: { keepExistingData?: boolean }): Promise<WritableFileStreamLike>;
}

interface SavePickerWindow {
  showSaveFilePicker?: (options?: { suggestedName?: string }) => Promise<SaveFileHandleLike>;
}

export function saveFilePickerAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof (window as unknown as SavePickerWindow).showSaveFilePicker === 'function'
  );
}

/**
 * Ask where to save. Call this synchronously at the start of a click handler (transient activation).
 * Rejects with an AbortError when the user dismisses the picker.
 */
export function pickSaveFile(suggestedName: string): Promise<SaveFileHandleLike> {
  const picker = (window as unknown as SavePickerWindow).showSaveFilePicker;
  if (typeof picker !== 'function') {
    return Promise.reject(new Error('showSaveFilePicker is not supported by this browser'));
  }
  return picker.call(window, { suggestedName });
}

export function createFileSystemSink(handle: SaveFileHandleLike): FileSink {
  let writable: Promise<WritableFileStreamLike> | null = null;
  let state: 'open' | 'closed' | 'aborted' = 'open';
  const stream = () => (writable ??= handle.createWritable({ keepExistingData: false }));
  return {
    kind: 'file-system',
    async write(chunk) {
      if (state !== 'open') throw new Error(`write after ${state}`);
      await (await stream()).write(new Uint8Array(chunk));
    },
    async close() {
      if (state !== 'open') throw new Error(`close after ${state}`);
      state = 'closed';
      await (await stream()).close();
      return null;
    },
    async abort() {
      if (state !== 'open') return;
      state = 'aborted';
      if (writable) await writable.then((w) => w.abort()).catch(() => undefined);
    },
  };
}
