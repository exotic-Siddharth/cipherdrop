/**
 * Crypto throughput bench (spec section 14): STREAM encrypt/decrypt throughput on 64 MiB and the
 * Argon2id time at KDF_DEFAULT, printed as a markdown table. Node only; nothing imports this file.
 *
 * Run: `npx tsx packages/crypto/src/bench.ts` (or `npm run bench -w @cipherdrop/crypto`).
 */
import { cpus } from 'node:os';
import { CHUNK_SIZE, KDF_DEFAULT, KDF_MIN, type Argon2Params } from './constants';
import { randomBytes, toHex } from './encoding';
import { argon2id } from './kdf';
import { deriveFileKey, generateDropKey, generateFileId, sha256 } from './keys';
import { chunkCount, createChunkDecryptor, encryptChunk } from './stream';

const MiB = 1024 * 1024;
const TOTAL_BYTES = 64 * MiB;
const STREAM_ROUNDS = 5;
const ARGON2_ROUNDS = 3;

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const mibPerSecond = (bytes: number, ms: number) => bytes / MiB / (ms / 1000);

async function timeStream(plaintext: Uint8Array) {
  const key = await deriveFileKey(generateDropKey(), generateFileId());
  const n = chunkCount(plaintext.length);
  const encryptMs: number[] = [];
  const decryptMs: number[] = [];
  const sha256Ms: number[] = [];
  for (let round = 0; round < STREAM_ROUNDS; round++) {
    let started = performance.now();
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < n; i++) {
      const part = plaintext.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
      chunks.push(await encryptChunk(key, i, i === n - 1, part));
    }
    encryptMs.push(performance.now() - started);

    // The uploader also hashes every ciphertext chunk for X-Chunk-SHA256 (R5).
    started = performance.now();
    for (const chunk of chunks) toHex(await sha256(chunk));
    sha256Ms.push(performance.now() - started);

    started = performance.now();
    const decryptor = createChunkDecryptor(key, n);
    const parts: Uint8Array[] = [];
    for (const chunk of chunks) parts.push(await decryptor.decryptNext(chunk));
    decryptMs.push(performance.now() - started);

    // Verified outside the timed sections: a broken build must not report numbers.
    if (!decryptor.done() || !Buffer.concat(parts).equals(Buffer.from(plaintext))) {
      throw new Error('bench: decrypted data differs from the plaintext');
    }
  }
  return { encryptMs: median(encryptMs), decryptMs: median(decryptMs), sha256Ms: median(sha256Ms) };
}

async function timeArgon2(params: Argon2Params) {
  const salt = randomBytes(16);
  const ms: number[] = [];
  for (let round = 0; round < ARGON2_ROUNDS; round++) {
    const started = performance.now();
    await argon2id('correct horse battery staple', salt, params);
    ms.push(performance.now() - started);
  }
  return median(ms);
}

async function main() {
  const plaintext = randomBytes(TOTAL_BYTES);
  // Warm-up: JIT, WebCrypto key setup and the hash-wasm module compile.
  await timeStream(plaintext.subarray(0, 2 * CHUNK_SIZE));
  await argon2id('warm-up', randomBytes(16), KDF_MIN);

  const stream = await timeStream(plaintext);
  const argonDefault = await timeArgon2(KDF_DEFAULT);
  const argonMin = await timeArgon2(KDF_MIN);

  const cpu = cpus()[0]?.model.trim() ?? 'unknown CPU';
  const rows = [
    ['STREAM encrypt (AES-256-GCM, 4 MiB chunks)', '64 MiB', stream.encryptMs, TOTAL_BYTES],
    ['STREAM decrypt (in-order decryptor)', '64 MiB', stream.decryptMs, TOTAL_BYTES],
    ['SHA-256 of ciphertext chunks (X-Chunk-SHA256)', '64 MiB', stream.sha256Ms, TOTAL_BYTES],
  ] as const;
  const lines = [
    `Crypto bench: Node ${process.version}, ${process.platform}/${process.arch}, ${cpu}`,
    `(median of ${STREAM_ROUNDS} runs for the stream rows, ${ARGON2_ROUNDS} for Argon2id; single stream, sequential chunks)`,
    '',
    '| Operation | Input | Time | Throughput |',
    '|---|---|---:|---:|',
    ...rows.map(
      ([op, input, ms, bytes]) =>
        `| ${op} | ${input} | ${ms.toFixed(0)} ms | ${mibPerSecond(bytes, ms).toFixed(0)} MiB/s |`,
    ),
    `| Argon2id at KDF_DEFAULT (hash-wasm) | m=${KDF_DEFAULT.memoryKiB} KiB, t=${KDF_DEFAULT.iterations}, p=${KDF_DEFAULT.parallelism} | ${argonDefault.toFixed(0)} ms | - |`,
    `| Argon2id at KDF_MIN (hash-wasm) | m=${KDF_MIN.memoryKiB} KiB, t=${KDF_MIN.iterations}, p=${KDF_MIN.parallelism} | ${argonMin.toFixed(0)} ms | - |`,
  ];
  console.log(lines.join('\n'));
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
