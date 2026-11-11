// @vitest-environment node
import { LIMITS } from '@cipherdrop/shared';
import { describe, expect, it, vi } from 'vitest';
import {
  createBlobSink,
  createFileSystemSink,
  needsSavePicker,
  safeBlobType,
  type SaveFileHandleLike,
} from './sinks';

describe('Blob sink', () => {
  it('collects parts and produces the Blob on close', async () => {
    const sink = createBlobSink('text/plain');
    const buf = new Uint8Array([104, 105]);
    await sink.write(buf);
    buf.fill(0); // the sink copied the bytes
    await sink.write(new Uint8Array([33]));
    const blob = await sink.close();
    expect(await blob!.text()).toBe('hi!');
    expect(blob!.type).toBe('text/plain');
    await expect(sink.write(new Uint8Array(1))).rejects.toThrow(/after closed/);
  });

  it('abort discards everything and refuses later writes and close', async () => {
    const sink = createBlobSink('text/plain');
    await sink.write(new Uint8Array([1, 2, 3]));
    await sink.abort();
    await sink.abort();
    await expect(sink.close()).rejects.toThrow(/after aborted/);
  });

  it('only keeps plain MIME types', () => {
    expect(safeBlobType('image/png')).toBe('image/png');
    expect(safeBlobType('Text/Plain')).toBe('text/plain');
    expect(safeBlobType('text/html; charset=utf-8')).toBe('application/octet-stream');
    expect(safeBlobType('')).toBe('application/octet-stream');
    expect(safeBlobType('nonsense')).toBe('application/octet-stream');
  });
});

describe('File-system sink', () => {
  function fakeHandle() {
    const writable = {
      write: vi.fn(async (_d: Uint8Array) => undefined),
      close: vi.fn(async () => undefined),
      abort: vi.fn(async () => undefined),
    };
    const handle: SaveFileHandleLike = { createWritable: vi.fn(async () => writable) };
    return { handle, writable };
  }

  it('streams writes and closes the writable', async () => {
    const { handle, writable } = fakeHandle();
    const sink = createFileSystemSink(handle);
    await sink.write(new Uint8Array([1]));
    await sink.write(new Uint8Array([2]));
    expect(await sink.close()).toBeNull();
    expect(writable.write).toHaveBeenCalledTimes(2);
    expect(writable.close).toHaveBeenCalledTimes(1);
    expect(handle.createWritable).toHaveBeenCalledWith({ keepExistingData: false });
  });

  it('abort aborts the writable (the target file is left untouched)', async () => {
    const { handle, writable } = fakeHandle();
    const sink = createFileSystemSink(handle);
    await sink.write(new Uint8Array([1]));
    await sink.abort();
    expect(writable.abort).toHaveBeenCalledTimes(1);
    expect(writable.close).not.toHaveBeenCalled();
  });

  it('a 0-byte file still creates and closes the file', async () => {
    const { handle, writable } = fakeHandle();
    const sink = createFileSystemSink(handle);
    await sink.close();
    expect(writable.close).toHaveBeenCalledTimes(1);
  });
});

describe('needsSavePicker (R22)', () => {
  it('uses the picker only above 256 MiB', () => {
    expect(needsSavePicker(LIMITS.BLOB_SAVE_MAX_BYTES)).toBe(false);
    expect(needsSavePicker(LIMITS.BLOB_SAVE_MAX_BYTES + 1)).toBe(true);
  });
});
