/**
 * Chunked authenticated encryption: the STREAM construction (spec section 7.2,
 * Hoang-Reyhanitabar-Rogaway-Vizar 2015).
 *
 * nonce_i = 0x00 x 7 || uint32_be(i) || (i == chunkCount - 1 ? 0x01 : 0x00)
 * ct_i    = AES-GCM(fileKey, nonce_i, aad = "cipherdrop/v1/chunk", pt_i)   (len = len(pt_i) + 16)
 *
 * The position and the last-chunk flag are authenticated through the nonce, so reordering, dropping,
 * duplicating, truncating or extending chunks all fail authentication. Every file has its own key
 * (HKDF salted with its random fileId), so a (key, nonce) pair is never reused.
 */
import { AAD, CHUNK_SIZE, NONCE_BYTES, TAG_BYTES } from './constants';
import { bs, isUint8Array, utf8Encode } from './encoding';
import { IntegrityError } from './errors';
import { gcmDecrypt, gcmEncrypt, isAesGcmKey, isAuthFailure } from './internal';

/** The nonce counter is a uint32, so a file has at most 2^32 chunks (16 PiB at 4 MiB per chunk). */
const MAX_CHUNKS = 2 ** 32;
const CHUNK_AAD = utf8Encode(AAD.CHUNK);

/** Decrypts chunks strictly in order; `isLast` comes from the authenticated chunkCount. */
export interface ChunkDecryptor {
  /** Decrypt the next chunk. Throws IntegrityError on any failure, or when called after the last chunk. */
  decryptNext(ct: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
  /** True once the final chunk has been decrypted. A stream that ends before done() is an IntegrityError. */
  done(): boolean;
}

/** max(1, ceil(size / chunkSize)); a 0-byte file is a single empty chunk. */
export function chunkCount(size: number, chunkSize: number = CHUNK_SIZE): number {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError(`size must be a non-negative safe integer (got ${size})`);
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1) {
    throw new RangeError(`chunkSize must be a positive integer (got ${chunkSize})`);
  }
  // Integer ceiling: floating-point division can round across an integer near 2^53.
  const n = size === 0 ? 1 : Number((BigInt(size) + BigInt(chunkSize) - 1n) / BigInt(chunkSize));
  if (n > MAX_CHUNKS) {
    throw new RangeError(`${size} bytes need ${n} chunks; the nonce counter allows ${MAX_CHUNKS}`);
  }
  return n;
}

/** size + 16 x chunkCount(size). */
export function ciphertextSize(size: number, chunkSize: number = CHUNK_SIZE): number {
  const total = size + TAG_BYTES * chunkCount(size, chunkSize);
  if (!Number.isSafeInteger(total))
    throw new RangeError(`ciphertext size of ${size} bytes overflows`);
  return total;
}

/** 12-byte nonce for chunk i: seven zero bytes, uint32 big-endian i, then the last-chunk flag. */
export function chunkNonce(i: number, isLast: boolean): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(i) || i < 0 || i >= MAX_CHUNKS) {
    throw new RangeError(`chunk index must be an integer in [0, 2^32) (got ${i})`);
  }
  if (typeof isLast !== 'boolean') throw new TypeError('isLast must be a boolean');
  const nonce = new Uint8Array(NONCE_BYTES);
  new DataView(nonce.buffer).setUint32(7, i, false);
  nonce[11] = isLast ? 1 : 0;
  return nonce;
}

/** Encrypt plaintext chunk i. */
export async function encryptChunk(
  key: CryptoKey,
  i: number,
  isLast: boolean,
  pt: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  return gcmEncrypt(key, chunkNonce(i, isLast), CHUNK_AAD, bs(pt));
}

/** Decrypt ciphertext chunk i. Throws IntegrityError when authentication fails. */
export async function decryptChunk(
  key: CryptoKey,
  i: number,
  isLast: boolean,
  ct: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  return openChunk(key, i, chunkNonce(i, isLast), bs(ct));
}

/**
 * In-order decryptor that enforces chunk positions and the final-chunk flag.
 *
 * Positions are assigned in call order, and overlapping calls are decrypted one after another in that
 * order. After the first failure (tampering, or data after the final chunk) every later call is
 * refused, so no further plaintext is released from a stream that failed, and done() returns false.
 */
export function createChunkDecryptor(key: CryptoKey, chunkCount: number): ChunkDecryptor {
  if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > MAX_CHUNKS) {
    throw new RangeError(`chunkCount must be an integer in [1, 2^32] (got ${chunkCount})`);
  }
  if (!isAesGcmKey(key, 'decrypt')) {
    throw new TypeError('createChunkDecryptor needs an AES-GCM CryptoKey with the decrypt usage');
  }
  let next = 0;
  let decrypted = 0;
  let failure: IntegrityError | null = null;
  let queue: Promise<unknown> = Promise.resolve();
  const refuse = () =>
    new IntegrityError('The stream already failed authentication', { cause: failure });

  return {
    decryptNext(ct: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
      if (!isUint8Array(ct)) {
        return Promise.reject(new TypeError('decryptNext expects a Uint8Array'));
      }
      if (failure) return Promise.reject(refuse());
      if (next >= chunkCount) {
        failure = new IntegrityError('Unexpected data after the final chunk');
        return Promise.reject(failure);
      }
      const i = next++;
      const nonce = chunkNonce(i, i === chunkCount - 1);
      // Copied now: the caller may reuse its buffer before this chunk's turn comes.
      const sealed = bs(ct);
      const result = queue.then(async () => {
        if (failure) throw refuse();
        try {
          const pt = await openChunk(key, i, nonce, sealed);
          decrypted++;
          return pt;
        } catch (e) {
          failure =
            e instanceof IntegrityError
              ? e
              : new IntegrityError(`Chunk ${i} could not be decrypted`, { cause: e });
          throw failure;
        }
      });
      queue = result.catch(() => undefined);
      return result;
    },
    done: () => failure === null && decrypted === chunkCount,
  };
}

async function openChunk(
  key: CryptoKey,
  i: number,
  nonce: Uint8Array<ArrayBuffer>,
  sealed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (sealed.length < TAG_BYTES) {
    throw new IntegrityError(`Chunk ${i} is shorter than its authentication tag`);
  }
  try {
    return await gcmDecrypt(key, nonce, CHUNK_AAD, sealed);
  } catch (e) {
    if (isAuthFailure(e)) {
      throw new IntegrityError(
        `Chunk ${i} failed authentication: it was modified, moved, truncated or is from another file`,
        { cause: e },
      );
    }
    throw e;
  }
}
