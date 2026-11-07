import { defineConfig } from 'vitest/config';

/**
 * @cipherdrop/crypto unit tests. They run in Node (WebCrypto via globalThis.crypto.subtle, Argon2id via
 * hash-wasm), which is also where the independent references used by the tests live: node:crypto and
 * @node-rs/argon2 (R20).
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Argon2id runs at up to KDF_MAX (256 MiB, t=10, p=4: about 4 s in WASM on a laptop).
    testTimeout: 60_000,
    // The laptop is shared with other jobs: cap the worker count.
    maxWorkers: 4,
    minWorkers: 1,
  },
});
