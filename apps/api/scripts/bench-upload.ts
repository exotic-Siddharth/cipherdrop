/**
 * Upload and download throughput bench against a RUNNING API (spec section 14 `bench`), printed as a markdown
 * table. `npm run bench -w @cipherdrop/api`, or `npm run bench` at the root together with the crypto bench.
 *
 * It registers its own throw-away account (never a seeded one), runs everything as that user and deletes the
 * account at the end (DELETE /me removes its drops and blobs), so the seeded dev data is untouched. The API must
 * allow 5 registrations per hour per IP (the default rate limits); set BENCH_EMAIL + BENCH_PASSWORD to reuse an
 * existing account instead (it is then NOT deleted, only the bench drops are).
 *
 * What is timed, per run of BENCH_SIZE_MIB MiB (random data, 4 MiB chunks, so 24 chunks for the default 96 MiB):
 *   - upload only: the ciphertext and the X-Chunk-SHA256 headers are prepared before the timer starts; the timer
 *     covers POST /drops, every chunk PUT and POST /drops/:id/complete, at 1 and at BENCH_CONCURRENCY chunks in flight;
 *   - encrypt + upload: AES-256-GCM encryption and SHA-256 of each chunk happen inside the timer, at
 *     BENCH_CONCURRENCY chunks in flight (the SPA's upload worker uses 3);
 *   - download only: POST /drops/:id/open plus every chunk GET, BENCH_CONCURRENCY in flight, bytes discarded;
 *   - download + decrypt: the same, with the in-order STREAM decryptor consuming the chunks as they arrive.
 * Every decrypted download is verified (the bytes must equal the plaintext) outside the timer.
 * Rates are MiB/s (1 MiB = 1,048,576 bytes) of plaintext.
 *
 * Env: BENCH_API_URL (default http://localhost:<API_PORT>), BENCH_SIZE_MIB (96), BENCH_RUNS (3),
 * BENCH_CONCURRENCY (3), BENCH_EMAIL, BENCH_PASSWORD. One untimed warm-up pass (16 MiB) runs first.
 */
import { cpus } from 'node:os';
import {
  AAD,
  b64urlEncode,
  CHUNK_SIZE,
  chunkCount as chunkCountFor,
  ciphertextSize,
  createAccountBundle,
  createChunkDecryptor,
  deriveAccountKeys,
  deriveFileKey,
  encryptChunk,
  encryptManifest,
  generateDropKey,
  generateFileId,
  importAesKey,
  KDF_MIN,
  randomBytes,
  sha256,
  toHex,
  unwrapKey,
  wrapKey,
} from '@cipherdrop/crypto';
import { LoginResponseSchema, PreloginResponseSchema } from '@cipherdrop/shared';
import { env } from '../src/config/env';

const MiB = 1024 * 1024;
const API = (process.env.BENCH_API_URL ?? `http://localhost:${env.API_PORT}`).replace(/\/$/, '');
const SIZE_MIB = Number(process.env.BENCH_SIZE_MIB ?? 96);
const RUNS = Number(process.env.BENCH_RUNS ?? 3);
const CONCURRENCY = Number(process.env.BENCH_CONCURRENCY ?? 3);
if (![SIZE_MIB, RUNS, CONCURRENCY].every((n) => Number.isInteger(n) && n >= 1)) {
  throw new Error('BENCH_SIZE_MIB, BENCH_RUNS and BENCH_CONCURRENCY must be positive integers');
}

interface Session {
  email: string;
  password: string;
  token: string;
  vaultKey: CryptoKey;
  created: boolean;
}

async function call(path: string, init: RequestInit & { token?: string } = {}): Promise<unknown> {
  const { token, ...rest } = init;
  const res = await fetch(`${API}/api${path}`, {
    ...rest,
    headers: {
      ...(typeof rest.body === 'string' ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(rest.headers as Record<string, string> | undefined),
    },
  });
  const isJson = res.headers.get('content-type')?.includes('json') ?? false;
  const body: unknown =
    res.status === 204
      ? null
      : isJson
        ? await res.json().catch(() => null)
        : await res.arrayBuffer();
  if (!res.ok) {
    throw new Error(`${rest.method ?? 'GET'} ${path} -> ${res.status} ${JSON.stringify(body)}`);
  }
  return body;
}

async function login(email: string, password: string) {
  const { kdf } = PreloginResponseSchema.parse(
    await call('/auth/prelogin', { method: 'POST', body: JSON.stringify({ email }) }),
  );
  const { authKey, encKey } = await deriveAccountKeys(password, kdf);
  const res = LoginResponseSchema.parse(
    await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, authKey: b64urlEncode(authKey) }),
    }),
  );
  if (res.mfaRequired) throw new Error('the bench account requires MFA');
  return { token: res.accessToken, authKey, encKey };
}

async function openSession(): Promise<Session> {
  const reuse = Boolean(process.env.BENCH_EMAIL && process.env.BENCH_PASSWORD);
  const email = process.env.BENCH_EMAIL ?? `bench-${Date.now().toString(36)}@bench.cipherdrop.test`;
  const password = process.env.BENCH_PASSWORD ?? `bench ${toHex(randomBytes(6))} horse battery`;
  if (!reuse) {
    const bundle = await createAccountBundle(password, KDF_MIN);
    await call('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email,
        authKey: b64urlEncode(bundle.authKey),
        kdf: bundle.kdf,
        wrappedAccountKey: bundle.wrappedAccountKey,
        wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
        recoveryAuthHash: bundle.recoveryAuthHash,
      }),
    });
  }
  const { token, encKey } = await login(email, password);
  const vault = (await call('/auth/vault', { token })) as { wrappedAccountKey: string };
  const accountKey = await unwrapKey(encKey, vault.wrappedAccountKey, AAD.WRAP_ACCOUNT);
  const vaultKey = await importAesKey(accountKey);
  accountKey.fill(0);
  return { email, password, token, vaultKey, created: !reuse };
}

async function deleteAccount(s: Session): Promise<void> {
  const { token, authKey } = await login(s.email, s.password);
  await call('/me', {
    method: 'DELETE',
    token,
    body: JSON.stringify({ authKey: b64urlEncode(authKey) }),
  });
}

/** Run `fn(i)` for i in [0, n) with at most `width` in flight. */
async function pool(n: number, width: number, fn: (i: number) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(width, n) }, async () => {
    while (next < n) await fn(next++);
  });
  await Promise.all(workers);
}

interface PreparedDrop {
  plaintext: Uint8Array<ArrayBuffer>;
  dk: Uint8Array<ArrayBuffer>;
  fileId: string;
  count: number;
}

async function encryptAt(
  d: PreparedDrop,
  fileKey: CryptoKey,
  i: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const part = d.plaintext.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
  return encryptChunk(fileKey, i, i === d.count - 1, part);
}

async function createDrop(s: Session, d: PreparedDrop) {
  const encryptedManifest = await encryptManifest(d.dk, {
    v: 1,
    createdAt: Date.now(),
    note: null,
    files: [
      {
        id: d.fileId,
        name: 'bench.bin',
        size: d.plaintext.length,
        type: 'application/octet-stream',
        lastModified: Date.now(),
        chunkSize: CHUNK_SIZE,
        chunkCount: d.count,
      },
    ],
  });
  const body = {
    encryptedManifest,
    files: [
      { id: d.fileId, ciphertextBytes: ciphertextSize(d.plaintext.length), chunkCount: d.count },
    ],
    expiresInHours: 1,
    maxDownloads: 100,
    ownerWrappedKey: await wrapKey(s.vaultKey, d.dk, AAD.WRAP_OWNER),
  };
  return (await call('/drops', { method: 'POST', token: s.token, body: JSON.stringify(body) })) as {
    dropId: string;
    uploadToken: string;
  };
}

interface Ready {
  cts: Uint8Array<ArrayBuffer>[];
  hashes: string[];
}

/** Upload one drop. `ready` = ciphertext + hashes prepared beforehand (upload only); null = encrypt inside. */
async function upload(
  s: Session,
  d: PreparedDrop,
  fileKey: CryptoKey,
  width: number,
  ready: Ready | null,
): Promise<{ dropId: string; ms: number }> {
  const started = performance.now();
  const drop = await createDrop(s, d);
  await pool(d.count, width, async (i) => {
    const ct = ready ? ready.cts[i] : await encryptAt(d, fileKey, i);
    const hash = ready ? ready.hashes[i] : toHex(await sha256(ct));
    await call(`/drops/${drop.dropId}/files/${d.fileId}/chunks/${i}`, {
      method: 'PUT',
      token: drop.uploadToken,
      headers: { 'content-type': 'application/octet-stream', 'x-chunk-sha256': hash },
      body: ct,
    });
  });
  await call(`/drops/${drop.dropId}/complete`, { method: 'POST', token: drop.uploadToken });
  return { dropId: drop.dropId, ms: performance.now() - started };
}

async function download(
  dropId: string,
  d: PreparedDrop,
  fileKey: CryptoKey,
  width: number,
  decrypt: boolean,
): Promise<{ ms: number; plain: Uint8Array[] }> {
  const started = performance.now();
  const open = (await call(`/drops/${dropId}/open`, { method: 'POST', body: '{}' })) as {
    downloadToken: string;
  };
  const decryptor = decrypt ? createChunkDecryptor(fileKey, d.count) : null;
  const plain: Uint8Array[] = [];
  const fetched: Promise<Uint8Array>[] = [];
  let nextFetch = 0;
  const startNext = () => {
    const i = nextFetch++;
    fetched[i] = call(`/drops/${dropId}/files/${d.fileId}/chunks/${i}`, {
      token: open.downloadToken,
    }).then((buf) => new Uint8Array(buf as ArrayBuffer));
  };
  // Keep `width` fetches ahead of the consumer; consume strictly in order, like the SPA downloader.
  while (nextFetch < Math.min(width, d.count)) startNext();
  for (let i = 0; i < d.count; i++) {
    const ct = await fetched[i];
    if (nextFetch < d.count) startNext();
    plain.push(decryptor ? await decryptor.decryptNext(ct) : ct);
  }
  const ms = performance.now() - started;
  if (decryptor && !decryptor.done()) throw new Error('bench: stream incomplete');
  return { ms, plain };
}

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const rate = (bytes: number, ms: number) => bytes / MiB / (ms / 1000);

async function one(s: Session, sizeMiB: number, width: number): Promise<Record<string, number>> {
  const d: PreparedDrop = {
    plaintext: randomBytes(sizeMiB * MiB),
    dk: generateDropKey(),
    fileId: generateFileId(),
    count: chunkCountFor(sizeMiB * MiB),
  };
  const fileKey = await deriveFileKey(d.dk, d.fileId);
  const total = d.plaintext.length;
  const remove = (id: string) => call(`/drops/${id}`, { method: 'DELETE', token: s.token });
  const out: Record<string, number> = {};

  // Ciphertext for the upload-only rows, built outside every timer.
  const cts: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < d.count; i++) cts.push(await encryptAt(d, fileKey, i));
  const hashes = await Promise.all(cts.map(async (c) => toHex(await sha256(c))));
  const ready = { cts, hashes };

  const up1 = await upload(s, d, fileKey, 1, ready);
  out.upload1 = rate(total, up1.ms);
  await remove(up1.dropId);

  const upN = await upload(s, d, fileKey, width, ready);
  out.uploadN = rate(total, upN.ms);
  const dl = await download(upN.dropId, d, fileKey, width, false);
  out.downloadN = rate(total, dl.ms);
  await remove(upN.dropId);

  const encUp = await upload(s, d, fileKey, width, null);
  out.encryptUploadN = rate(total, encUp.ms);
  const dlDec = await download(encUp.dropId, d, fileKey, width, true);
  out.downloadDecryptN = rate(total, dlDec.ms);
  // Verified outside the timers: a broken build must not report numbers.
  if (!Buffer.concat(dlDec.plain).equals(Buffer.from(d.plaintext))) {
    throw new Error('bench: downloaded data differs from the plaintext');
  }
  await remove(encUp.dropId);
  return out;
}

async function main(): Promise<void> {
  console.error(
    `Upload bench against ${API}: ${SIZE_MIB} MiB x ${RUNS} runs, ${CONCURRENCY} in flight`,
  );
  const s = await openSession();
  try {
    await one(s, 16, CONCURRENCY); // warm-up (JIT, connections, disk cache), not reported
    const runs: Record<string, number>[] = [];
    for (let r = 0; r < RUNS; r++) {
      runs.push(await one(s, SIZE_MIB, CONCURRENCY));
      console.error(`  run ${r + 1}/${RUNS} done`);
    }
    const rows: [string, string][] = [
      ['upload1', 'Upload only, 1 chunk in flight (ciphertext prepared)'],
      ['uploadN', `Upload only, ${CONCURRENCY} chunks in flight (ciphertext prepared)`],
      ['encryptUploadN', `Encrypt + SHA-256 + upload, ${CONCURRENCY} in flight`],
      ['downloadN', `Download only, ${CONCURRENCY} in flight`],
      ['downloadDecryptN', `Download + decrypt, ${CONCURRENCY} in flight`],
    ];
    const cpu = cpus()[0]?.model.trim() ?? 'unknown CPU';
    const raw = runs.map((run) =>
      Object.fromEntries(Object.entries(run).map(([k, v]) => [k, Number(v.toFixed(1))])),
    );
    console.log(
      [
        `API bench: Node ${process.version}, ${process.platform}/${process.arch}, ${cpu}; API ${API}`,
        `(${SIZE_MIB} MiB random file, ${Math.ceil((SIZE_MIB * MiB) / CHUNK_SIZE)} chunks of 4 MiB, signed-in user, ${RUNS} runs after one warm-up)`,
        '',
        '| Operation | Median MiB/s | Min | Max |',
        '|---|---:|---:|---:|',
        ...rows.map(([key, label]) => {
          const xs = runs.map((run) => run[key]);
          return `| ${label} | ${median(xs).toFixed(1)} | ${Math.min(...xs).toFixed(1)} | ${Math.max(...xs).toFixed(1)} |`;
        }),
        '',
        `Raw runs (MiB/s): ${JSON.stringify(raw)}`,
      ].join('\n'),
    );
  } finally {
    if (s.created) {
      await deleteAccount(s).catch((e: unknown) => console.error('cleanup failed:', e));
    }
  }
}

main().catch((err: unknown) => {
  console.error('BENCH FAILED:', err instanceof Error ? err.message : err);
  if (err instanceof Error && err.cause) console.error('  cause:', err.cause);
  process.exitCode = 1;
});
