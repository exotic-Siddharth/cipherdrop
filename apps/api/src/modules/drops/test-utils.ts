/**
 * Test helpers for the drops, admin and cleanup suites (not imported by application code).
 *
 * The server only sees opaque ciphertext, so most tests upload random bytes of the exact ciphertext sizes a
 * real client would produce (spec section 7.2). The lifecycle test in drops.download.test.ts uses
 * @cipherdrop/crypto end to end.
 */
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { LIMITS, type CreateDropRequest } from '@cipherdrop/shared';
import type { Express } from 'express';
import request from 'supertest';

export const CT_CHUNK = LIMITS.CHUNK_SIZE + LIMITS.TAG_BYTES;

export const id16 = () => randomBytes(16).toString('base64url');
export const token32 = () => randomBytes(32).toString('base64url');
export const sha256Hex = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
export const sha256B64 = (b: Uint8Array) => createHash('sha256').update(b).digest('base64url');

/** A fake encrypted manifest (opaque to the server). */
export const fakeManifest = (bytes = 120) => randomBytes(bytes).toString('base64url');
/** A fake 80-char wrapped key. */
export const fakeWrappedKey = () => randomBytes(60).toString('base64url');

export interface TestFile {
  id: string;
  plainSize: number;
  chunkCount: number;
  ciphertextBytes: number;
  /** Ciphertext size of every chunk. */
  chunkSizes: number[];
}

/** Ciphertext layout of a plaintext file of `plainSize` bytes. */
export function testFile(plainSize: number): TestFile {
  const chunkCount = Math.max(1, Math.ceil(plainSize / LIMITS.CHUNK_SIZE));
  const chunkSizes = Array.from({ length: chunkCount }, (_, i) =>
    i < chunkCount - 1 ? CT_CHUNK : plainSize - i * LIMITS.CHUNK_SIZE + LIMITS.TAG_BYTES,
  );
  return {
    id: id16(),
    plainSize,
    chunkCount,
    ciphertextBytes: plainSize + LIMITS.TAG_BYTES * chunkCount,
    chunkSizes,
  };
}

/** Random "ciphertext" of the right size for chunk `index` of `f`. */
export const chunkData = (f: TestFile, index: number) => randomBytes(f.chunkSizes[index] ?? 0);

export interface PasswordFixture {
  authKey: string;
  password: NonNullable<CreateDropRequest['password']>;
}

export function passwordFixture(): PasswordFixture {
  const authKeyBytes = randomBytes(32);
  return {
    authKey: authKeyBytes.toString('base64url'),
    password: {
      kdf: { salt: id16(), memoryKiB: 19456, iterations: 2, parallelism: 1 },
      wrappedDropKey: fakeWrappedKey(),
      authKeyHash: sha256B64(authKeyBytes),
    },
  };
}

export function createBody(
  files: TestFile[],
  overrides: Partial<Omit<CreateDropRequest, 'files'>> & { files?: unknown } = {},
): Record<string, unknown> {
  return {
    encryptedManifest: fakeManifest(),
    files: files.map((f) => ({
      id: f.id,
      ciphertextBytes: f.ciphertextBytes,
      chunkCount: f.chunkCount,
    })),
    expiresInHours: 24,
    maxDownloads: 5,
    ...overrides,
  };
}

export interface CreatedDrop {
  dropId: string;
  ownerToken: string;
  uploadToken: string;
  expiresAt: string;
}

export async function postDrop(
  app: Express,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  return request(app).post('/api/drops').set(headers).send(body);
}

export async function createDropOk(
  app: Express,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<CreatedDrop> {
  const res = await postDrop(app, body, headers);
  if (res.status !== 201)
    throw new Error(`create failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body as CreatedDrop;
}

export function putChunk(
  app: Express,
  dropId: string,
  uploadToken: string | null,
  fileId: string,
  index: number | string,
  data: Buffer,
  sha: string | null = sha256Hex(data),
) {
  let req = request(app)
    .put(`/api/drops/${dropId}/files/${fileId}/chunks/${index}`)
    .set('Content-Type', 'application/octet-stream');
  if (uploadToken) req = req.set('Authorization', `Bearer ${uploadToken}`);
  if (sha !== null) req = req.set('X-Chunk-SHA256', sha);
  return req.send(data);
}

/** Upload every chunk of every file; returns the uploaded bytes per file id. */
export async function uploadAll(
  app: Express,
  drop: CreatedDrop,
  files: TestFile[],
): Promise<Map<string, Buffer[]>> {
  const out = new Map<string, Buffer[]>();
  for (const f of files) {
    const chunks: Buffer[] = [];
    for (let i = 0; i < f.chunkCount; i++) {
      const data = chunkData(f, i);
      const res = await putChunk(app, drop.dropId, drop.uploadToken, f.id, i, data);
      if (res.status !== 204)
        throw new Error(`chunk PUT failed: ${res.status} ${JSON.stringify(res.body)}`);
      chunks.push(data);
    }
    out.set(f.id, chunks);
  }
  return out;
}

export function complete(app: Express, drop: Pick<CreatedDrop, 'dropId' | 'uploadToken'>) {
  return request(app)
    .post(`/api/drops/${drop.dropId}/complete`)
    .set('Authorization', `Bearer ${drop.uploadToken}`)
    .send();
}

export interface ReadyDrop extends CreatedDrop {
  files: TestFile[];
  chunks: Map<string, Buffer[]>;
}

/** Create, upload and complete a drop. */
export async function createReadyDrop(
  app: Express,
  options: {
    files?: TestFile[];
    body?: Partial<CreateDropRequest>;
    headers?: Record<string, string>;
  } = {},
): Promise<ReadyDrop> {
  const files = options.files ?? [testFile(1000)];
  const drop = await createDropOk(app, createBody(files, options.body), options.headers);
  const chunks = await uploadAll(app, drop, files);
  const res = await complete(app, drop);
  if (res.status !== 200)
    throw new Error(`complete failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { ...drop, files, chunks };
}

export function openDrop(
  app: Express,
  dropId: string,
  body: Record<string, unknown> = {},
  headers: Record<string, string> = {},
) {
  return request(app).post(`/api/drops/${dropId}/open`).set(headers).send(body);
}

export function getChunk(
  app: Express,
  dropId: string,
  downloadToken: string | null,
  fileId: string,
  index: number,
) {
  let req = request(app).get(`/api/drops/${dropId}/files/${fileId}/chunks/${index}`);
  if (downloadToken) req = req.set('Authorization', `Bearer ${downloadToken}`);
  return req.buffer(true).parse((res, cb) => {
    const parts: Buffer[] = [];
    res.on('data', (c: Buffer) => parts.push(c));
    res.on('end', () => cb(null, Buffer.concat(parts)));
  });
}

/**
 * The blob files the local driver holds for one chunk: `<index>` (legacy) or `<index>.<version>` (one per
 * PUT attempt, C-R2-01). Temp files are not counted. Independent of the DropChunk rows, so it also sees
 * orphans.
 */
export async function chunkBlobFiles(
  storageDir: string,
  dropId: string,
  fileId: string,
  index: number,
): Promise<string[]> {
  let names: string[];
  try {
    names = await fs.promises.readdir(path.join(storageDir, dropId, fileId));
  } catch (err) {
    if ((err as { code?: string }).code === 'ENOENT') return [];
    throw err;
  }
  return names.filter((n) => n === String(index) || n.startsWith(`${index}.`));
}

/** A mutable clock for createTestApp({ now }). */
export function testClock(start = new Date()) {
  let current = start.getTime();
  return {
    now: () => new Date(current),
    set: (d: Date) => {
      current = d.getTime();
    },
    advance: (ms: number) => {
      current += ms;
    },
  };
}

/**
 * Current value of a Prometheus sample as exposed by the app's /metrics (sums matching series). Read through
 * the app rather than importing lib/metrics, so the test sees the registry the app really uses.
 */
export async function metricValue(app: Express, name: string, labels = ''): Promise<number> {
  const res = await request(app).get('/metrics');
  let total = 0;
  for (const line of String(res.text).split(/\r?\n/)) {
    if (line.startsWith('#')) continue;
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)$/.exec(line.trim());
    if (!m || m[1] !== name) continue;
    if (labels && !(m[2] ?? '').includes(labels)) continue;
    total += Number(m[3]);
  }
  return total;
}

/** JSON.stringify that tolerates BigInt columns. */
export const toJson = (v: unknown) =>
  JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? Number(x) : x));

export const MIN = 60_000;
export const HOUR = 60 * MIN;
