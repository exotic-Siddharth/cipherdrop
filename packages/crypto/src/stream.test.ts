// @vitest-environment node
import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { IntegrityError } from './errors';
import { deriveFileKey, generateDropKey, generateFileId, importAesKey } from './keys';
import {
  chunkCount,
  chunkNonce,
  ciphertextSize,
  createChunkDecryptor,
  decryptChunk,
  encryptChunk,
} from './stream';

/** Spec 7.1 CHUNK_SIZE, typed here from the spec. */
const MiB4 = 4 * 1024 * 1024;
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const random = (n: number) => new Uint8Array(nodeRandomBytes(n));
const sameBytes = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const newFileKey = async () => deriveFileKey(generateDropKey(), generateFileId());

/** Encrypt the way the uploader does: split at chunkSize; chunk i is flagged last iff i == n - 1. */
async function encryptFile(key: CryptoKey, pt: Uint8Array, chunkSize = MiB4) {
  const n = Math.max(1, Math.ceil(pt.length / chunkSize));
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const part = pt.subarray(i * chunkSize, (i + 1) * chunkSize);
    chunks.push(await encryptChunk(key, i, i === n - 1, part));
  }
  return chunks;
}

/** Decrypt the way the downloader does: in order, then insist that the stream reached its end. */
async function decryptFile(key: CryptoKey, chunks: Uint8Array[], count = chunks.length) {
  const decryptor = createChunkDecryptor(key, count);
  const parts: Uint8Array[] = [];
  for (const chunk of chunks) parts.push(await decryptor.decryptNext(chunk));
  if (!decryptor.done()) throw new IntegrityError('stream ended before its final chunk');
  return Buffer.concat(parts);
}

describe('chunk roundtrip', () => {
  it.each([
    ['0 B', 0, [16]],
    ['1 B', 1, [17]],
    ['CHUNK_SIZE - 1', MiB4 - 1, [MiB4 + 15]],
    ['CHUNK_SIZE', MiB4, [MiB4 + 16]],
    ['CHUNK_SIZE + 1', MiB4 + 1, [MiB4 + 16, 17]],
    ['3 chunks', 2 * MiB4 + 12_345, [MiB4 + 16, MiB4 + 16, 12_345 + 16]],
  ])('%s', async (_, size, ciphertextChunkSizes) => {
    const key = await newFileKey();
    const pt = random(size);
    const chunks = await encryptFile(key, pt);
    expect(chunks.map((c) => c.length)).toEqual(ciphertextChunkSizes);
    expect(chunkCount(size)).toBe(ciphertextChunkSizes.length);
    expect(ciphertextSize(size)).toBe(ciphertextChunkSizes.reduce((a, b) => a + b, 0));
    expect(sameBytes(await decryptFile(key, chunks), pt)).toBe(true);
  });

  it('0-byte file roundtrip', async () => {
    // A 0-byte file is one empty chunk: just the 16-byte tag, flagged as the last chunk.
    const key = await newFileKey();
    expect(chunkCount(0)).toBe(1);
    const ct = await encryptChunk(key, 0, true, new Uint8Array(0));
    expect(ct).toHaveLength(16);
    const decryptor = createChunkDecryptor(key, 1);
    expect(decryptor.done()).toBe(false);
    expect(await decryptor.decryptNext(ct)).toHaveLength(0);
    expect(decryptor.done()).toBe(true);
  });
});

describe('tampering', () => {
  /** Three chunks with a small chunk size: STREAM's guarantees do not depend on the chunk size. */
  async function threeChunks() {
    const key = await newFileKey();
    const pt = random(2_500);
    return { key, pt, chunks: await encryptFile(key, pt, 1_000) };
  }

  it('a flipped ciphertext bit → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    // A body byte of chunk 0, a body byte of chunk 1, and the last tag byte of the final chunk.
    for (const [chunk, offset] of [
      [0, 0],
      [1, 500],
      [2, chunks[2].length - 1],
    ]) {
      const forged = chunks.map((c) => c.slice());
      forged[chunk][offset] ^= 0x01;
      await expect(decryptFile(key, forged)).rejects.toBeInstanceOf(IntegrityError);
    }
  });

  it('swapped chunks → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    await expect(decryptFile(key, [chunks[1], chunks[0], chunks[2]])).rejects.toBeInstanceOf(
      IntegrityError,
    );
  });

  it('a duplicated chunk → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    await expect(decryptFile(key, [chunks[0], chunks[0], chunks[2]])).rejects.toBeInstanceOf(
      IntegrityError,
    );
  });

  it('a dropped final chunk → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    // With the true chunkCount (from the authenticated manifest) the stream never completes...
    const honest = createChunkDecryptor(key, 3);
    await honest.decryptNext(chunks[0]);
    await honest.decryptNext(chunks[1]);
    expect(honest.done()).toBe(false);
    // ...and passing the penultimate chunk off as the last one fails authentication (flag 0x00).
    await expect(decryptFile(key, chunks.slice(0, 2), 2)).rejects.toBeInstanceOf(IntegrityError);
  });

  it('a final chunk replayed as non-final → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    // Extension: a 4-chunk stream whose third chunk is the real final chunk (flag 0x01 at index 2).
    const decryptor = createChunkDecryptor(key, 4);
    await decryptor.decryptNext(chunks[0]);
    await decryptor.decryptNext(chunks[1]);
    await expect(decryptor.decryptNext(chunks[2])).rejects.toBeInstanceOf(IntegrityError);
    await expect(decryptChunk(key, 2, false, chunks[2])).rejects.toBeInstanceOf(IntegrityError);
  });

  it('a chunk appended after the final chunk → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    const decryptor = createChunkDecryptor(key, 3);
    for (const chunk of chunks) await decryptor.decryptNext(chunk);
    expect(decryptor.done()).toBe(true);
    await expect(decryptor.decryptNext(chunks[2])).rejects.toBeInstanceOf(IntegrityError);
  });

  it('a chunk shorter than the tag → IntegrityError', async () => {
    const { key, chunks } = await threeChunks();
    await expect(decryptChunk(key, 0, false, chunks[0].subarray(0, 15))).rejects.toBeInstanceOf(
      IntegrityError,
    );
  });

  it('the wrong file key fails', async () => {
    const dk = generateDropKey();
    const fileId = generateFileId();
    const ct = await encryptChunk(await deriveFileKey(dk, fileId), 0, true, random(100));
    // Another file of the same drop, and the same fileId under another drop key.
    const otherFile = await deriveFileKey(dk, generateFileId());
    const otherDrop = await deriveFileKey(generateDropKey(), fileId);
    for (const key of [otherFile, otherDrop]) {
      await expect(decryptChunk(key, 0, true, ct)).rejects.toBeInstanceOf(IntegrityError);
    }
  });

  it('refuses every chunk after the first integrity failure', async () => {
    const { key, chunks } = await threeChunks();
    const forged = chunks[0].slice();
    forged[3] ^= 0x80;
    const decryptor = createChunkDecryptor(key, 3);
    await expect(decryptor.decryptNext(forged)).rejects.toBeInstanceOf(IntegrityError);
    // chunks[1] would be valid at index 1, but no plaintext is released once the stream failed.
    await expect(decryptor.decryptNext(chunks[1])).rejects.toBeInstanceOf(IntegrityError);
    expect(decryptor.done()).toBe(false);
  });

  it('decrypts overlapping decryptNext calls in call order', async () => {
    const { key, pt, chunks } = await threeChunks();
    const decryptor = createChunkDecryptor(key, 3);
    const parts = await Promise.all(chunks.map((c) => decryptor.decryptNext(c)));
    expect(sameBytes(Buffer.concat(parts), pt)).toBe(true);
    expect(decryptor.done()).toBe(true);
  });
});

describe('chunkNonce', () => {
  it('is seven zero bytes, the uint32 big-endian index, then the last-chunk flag', () => {
    expect(hex(chunkNonce(0, false))).toBe('000000000000000000000000');
    expect(hex(chunkNonce(0, true))).toBe('000000000000000000000001');
    expect(hex(chunkNonce(1, false))).toBe('000000000000000000000100');
    expect(hex(chunkNonce(0x01020304, true))).toBe('000000000000000102030401');
    expect(hex(chunkNonce(0xffffffff, true))).toBe('00000000000000ffffffff01');
  });

  it('rejects indexes outside the uint32 range', () => {
    for (const i of [-1, 2 ** 32, 1.5, Number.NaN]) {
      expect(() => chunkNonce(i, false), String(i)).toThrow(RangeError);
    }
  });
});

describe('chunkCount / ciphertextSize', () => {
  it.each([
    [0, 1, 16],
    [1, 1, 17],
    [MiB4 - 1, 1, MiB4 + 15],
    [MiB4, 1, MiB4 + 16],
    [MiB4 + 1, 2, MiB4 + 33],
    [3 * MiB4, 3, 3 * MiB4 + 48],
    [2 * 1024 ** 3, 512, 2 * 1024 ** 3 + 512 * 16],
  ])('size %i → %i chunks and %i ciphertext bytes', (size, n, total) => {
    expect(chunkCount(size)).toBe(n);
    expect(ciphertextSize(size)).toBe(total);
  });

  it('honours an explicit chunk size', () => {
    expect(chunkCount(9, 3)).toBe(3);
    expect(chunkCount(10, 3)).toBe(4);
    expect(ciphertextSize(10, 3)).toBe(10 + 4 * 16);
  });

  it('rejects negative, fractional or unsafe sizes and non-positive chunk sizes', () => {
    for (const size of [-1, 0.5, Number.NaN, 2 ** 53]) {
      expect(() => chunkCount(size), String(size)).toThrow(RangeError);
    }
    for (const chunkSize of [0, -4, 1.5]) {
      expect(() => chunkCount(10, chunkSize), String(chunkSize)).toThrow(RangeError);
    }
  });

  it('refuses more chunks than the uint32 nonce counter can address', () => {
    expect(chunkCount(2 ** 32, 1)).toBe(2 ** 32);
    expect(() => chunkCount(2 ** 32 + 1, 1)).toThrow(RangeError);
  });
});

describe('createChunkDecryptor', () => {
  it('rejects a chunk count outside 1 .. 2^32', async () => {
    const key = await newFileKey();
    for (const n of [0, 1.5, 2 ** 32 + 1]) {
      expect(() => createChunkDecryptor(key, n), String(n)).toThrow(RangeError);
    }
  });

  it('rejects a key that cannot AES-GCM decrypt', async () => {
    const encryptOnly = await crypto.subtle.importKey('raw', random(32), 'AES-GCM', false, [
      'encrypt',
    ]);
    expect(() => createChunkDecryptor(encryptOnly, 1)).toThrow(TypeError);
    expect(() => createChunkDecryptor({} as CryptoKey, 1)).toThrow(TypeError);
    // A decrypt-capable AES-GCM key from importAesKey is fine.
    const usable = await importAesKey(random(32));
    expect(() => createChunkDecryptor(usable, 1)).not.toThrow();
  });
});
