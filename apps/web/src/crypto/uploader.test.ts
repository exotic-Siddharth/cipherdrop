// @vitest-environment node
import {
  CHUNK_SIZE,
  createPasswordProtection,
  decryptChunk,
  decryptManifest,
  deriveFileKey,
  generateDropKey,
  importAesKey,
  KDF_MIN,
  sha256,
  toHex,
  unwrapKey,
  AAD,
  randomBytes,
} from '@cipherdrop/crypto';
import { CreateDropRequestSchema, type UploadStatus } from '@cipherdrop/shared';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../lib/http';
import {
  deserializeUploadError,
  prepareDrop,
  retryDelayFor,
  serializeUploadError,
  uploadDropFiles,
  verifyResume,
  type UploadEvent,
} from './uploader';

const DROP_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
const TOKEN = 'T'.repeat(43);

interface Captured {
  url: string;
  method: string;
  headers: Headers;
  body: Uint8Array;
}

function capturingFetch(
  respond: (req: Captured, n: number) => Response | Promise<Response> = () =>
    new Response(null, { status: 204 }),
) {
  const requests: Captured[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = init?.body;
    const bytes =
      body instanceof Uint8Array
        ? new Uint8Array(body)
        : body instanceof ArrayBuffer
          ? new Uint8Array(body)
          : new Uint8Array();
    const req: Captured = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: bytes,
    };
    requests.push(req);
    return respond(req, requests.length);
  });
  vi.stubGlobal('fetch', fn);
  return { requests, fn };
}

function textFile(name: string, text: string, type = 'text/plain'): File {
  return new File([text], name, { type, lastModified: 1_700_000_000_000 });
}

function bytesFile(name: string, size: number, fill: (i: number) => number): File {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = fill(i);
  return new File([data], name, { type: 'application/octet-stream', lastModified: 1 });
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

const noSleep = () => {
  const delays: number[] = [];
  return { delays, sleep: async (ms: number) => void delays.push(ms) };
};

async function jobFor(file: File) {
  const prepared = await prepareDrop({
    files: [file],
    note: null,
    expiresInHours: 24,
    maxDownloads: 1,
  });
  return prepared;
}

describe('uploadDropFiles', () => {
  it('retries with backoff then succeeds', async () => {
    const prepared = await jobFor(textFile('a.txt', 'hello world'));
    const { requests } = capturingFetch((_req, n) =>
      n <= 2
        ? new Response(JSON.stringify({ error: { code: 'INTERNAL', message: 'boom' } }), {
            status: 503,
          })
        : new Response(null, { status: 204 }),
    );
    const { delays, sleep } = noSleep();
    const events: UploadEvent[] = [];
    await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
      sleep,
      onEvent: (e) => events.push(e),
    });
    expect(requests).toHaveLength(3);
    expect(new Set(requests.map((r) => r.url)).size).toBe(1);
    expect(delays).toEqual([500, 2000]);
    expect(events.filter((e) => e.type === 'retry')).toHaveLength(2);
    expect(events.some((e) => e.type === 'chunk-uploaded')).toBe(true);
    expect(events.at(-1)).toMatchObject({ type: 'file-done', fileId: prepared.files[0]!.id });
  });

  it('honours Retry-After on 429', async () => {
    const prepared = await jobFor(textFile('a.txt', 'x'));
    capturingFetch((_req, n) =>
      n === 1
        ? new Response(JSON.stringify({ error: { code: 'RATE_LIMITED', message: 'slow' } }), {
            status: 429,
            headers: { 'retry-after': '7' },
          })
        : new Response(null, { status: 204 }),
    );
    const { delays, sleep } = noSleep();
    await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
      sleep,
    });
    expect(delays).toEqual([7000]);
  });

  it('gives up after three retries (0.5 s, 2 s, 8 s) with a retryable error', async () => {
    const prepared = await jobFor(textFile('a.txt', 'x'));
    const { requests } = capturingFetch(() => new Response(null, { status: 503 }));
    const { delays, sleep } = noSleep();
    const err = await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
      sleep,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).isRetryable).toBe(true);
    expect(requests).toHaveLength(4);
    expect(delays).toEqual([500, 2000, 8000]);
  });

  it('does not retry a 4xx other than 429', async () => {
    const prepared = await jobFor(textFile('a.txt', 'x'));
    const { requests } = capturingFetch(
      () =>
        new Response(JSON.stringify({ error: { code: 'CONFLICT', message: 'not uploading' } }), {
          status: 409,
        }),
    );
    const { delays, sleep } = noSleep();
    const err = await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
      sleep,
    }).catch((e: unknown) => e);
    expect((err as ApiError).code).toBe('CONFLICT');
    expect(requests).toHaveLength(1);
    expect(delays).toEqual([]);
  });

  it('keeps at most 3 chunk PUTs in flight', async () => {
    const files = Array.from({ length: 8 }, (_, i) => textFile(`f${i}.txt`, `file ${i}`));
    const prepared = await prepareDrop({ files, note: null, expiresInHours: 1, maxDownloads: 1 });
    let inFlight = 0;
    let peak = 0;
    const { requests } = capturingFetch(async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 15));
      inFlight--;
      return new Response(null, { status: 204 });
    });
    await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
    });
    expect(requests).toHaveLength(8);
    expect(peak).toBe(3);
  });

  it('skips chunks the server already has (resume)', async () => {
    const file = bytesFile('big.bin', CHUNK_SIZE * 2 + 5, (i) => i % 251);
    const prepared = await jobFor(file);
    const { requests } = capturingFetch();
    await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: [{ ...prepared.files[0]!, skip: [0, 1] }],
    });
    expect(requests.map((r) => r.url.split('/').at(-1))).toEqual(['2']);
  });

  it('stops on cancel and rejects with an AbortError', async () => {
    const files = Array.from({ length: 6 }, (_, i) => textFile(`f${i}.txt`, `file ${i}`));
    const prepared = await prepareDrop({ files, note: null, expiresInHours: 1, maxDownloads: 1 });
    const ctrl = new AbortController();
    const { requests } = capturingFetch(
      (_req, n) =>
        new Promise<Response>((resolve, reject) => {
          if (n === 2) ctrl.abort();
          if (ctrl.signal.aborted) {
            reject(new DOMException('aborted', 'AbortError'));
            return;
          }
          setTimeout(() => resolve(new Response(null, { status: 204 })), 5);
        }),
    );
    const err = await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
      signal: ctrl.signal,
    }).catch((e: unknown) => e);
    expect((err as Error).name).toBe('AbortError');
    expect(requests.length).toBeLessThanOrEqual(3);
  });

  it('sends only ciphertext and hashes (no request body or URL contains the file name or plaintext bytes)', async () => {
    const marker = 'TOP-SECRET-PLAINTEXT-MARKER:';
    const small = textFile('quarterly-secret-plans.txt', marker.repeat(40), 'text/x-secret-type');
    const bigName = 'board minutes ' + String.fromCodePoint(0x1f512) + '.pdf';
    const big = bytesFile(bigName, CHUNK_SIZE + 4096, (i) => marker.charCodeAt(i % marker.length));
    const empty = new File([], 'empty-file-name.dat', { lastModified: 5 });
    const accountRaw = randomBytes(32);
    const accountKey = await importAesKey(accountRaw);
    const prepared = await prepareDrop({
      files: [small, big, empty],
      note: 'meet behind the old library',
      expiresInHours: 24,
      maxDownloads: 3,
      password: 'correct horse battery staple',
      protect: (dk, pw) => createPasswordProtection(dk, pw, KDF_MIN),
      accountKey,
    });

    // The create body: validates against the shared contract and carries no plaintext metadata.
    const createBody = JSON.stringify(prepared.request);
    expect(CreateDropRequestSchema.safeParse(prepared.request).success).toBe(true);
    for (const secret of [
      'quarterly-secret-plans',
      'board minutes',
      'empty-file-name',
      'text/x-secret-type',
      'meet behind',
      'correct horse',
      marker,
    ]) {
      expect(createBody).not.toContain(secret);
    }
    expect(Object.keys(prepared.request).sort()).toEqual(
      [
        'encryptedManifest',
        'expiresInHours',
        'files',
        'maxDownloads',
        'ownerWrappedKey',
        'password',
      ].sort(),
    );
    expect(Object.keys(prepared.request.password!).sort()).toEqual(
      ['authKeyHash', 'kdf', 'wrappedDropKey'].sort(),
    );
    // The manifest and owner wrap decrypt to what we sent.
    const manifest = await decryptManifest(prepared.dk, prepared.request.encryptedManifest);
    expect(manifest.files.map((f) => f.name)).toEqual([small.name, bigName, empty.name]);
    expect(manifest.note).toBe('meet behind the old library');
    expect(await unwrapKey(accountKey, prepared.request.ownerWrappedKey!, AAD.WRAP_OWNER)).toEqual(
      prepared.dk,
    );

    const { requests } = capturingFetch();
    await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
    });
    expect(requests).toHaveLength(4); // 1 + 2 + 1 chunks

    const markerBytes = new TextEncoder().encode(marker.slice(0, 20));
    const names = [small.name, bigName, empty.name].map((n) => encodeURIComponent(n));
    for (const req of requests) {
      expect(req.method).toBe('PUT');
      for (const n of [...names, 'secret', 'board', 'empty-file']) expect(req.url).not.toContain(n);
      expect(req.url).toMatch(
        /\/api\/drops\/[A-Za-z0-9_-]+\/files\/[A-Za-z0-9_-]{22}\/chunks\/\d+$/,
      );
      expect(contains(req.body, markerBytes)).toBe(false);
      expect(req.headers.get('x-chunk-sha256')).toBe(toHex(await sha256(req.body)));
      expect(req.headers.get('authorization')).toBe(`Bearer ${TOKEN}`);
      expect(req.headers.get('content-type')).toBe('application/octet-stream');
      // No metadata headers beyond the contract.
      expect([...req.headers.keys()].sort()).toEqual(
        ['authorization', 'content-type', 'x-chunk-sha256'].sort(),
      );
    }

    // And the ciphertext is real: it decrypts back to the plaintext.
    const bigId = prepared.files[1]!.id;
    const bigKey = await deriveFileKey(prepared.dk, bigId);
    const bigReqs = requests
      .filter((r) => r.url.includes(`/files/${bigId}/`))
      .sort((a, b) => Number(a.url.split('/').at(-1)) - Number(b.url.split('/').at(-1)));
    const pt0 = await decryptChunk(bigKey, 0, false, bigReqs[0]!.body);
    const pt1 = await decryptChunk(bigKey, 1, true, bigReqs[1]!.body);
    expect(pt0.length + pt1.length).toBe(big.size);
    expect(new Uint8Array(await big.slice(0, 64).arrayBuffer())).toEqual(pt0.slice(0, 64));
  });
});

describe('prepareDrop', () => {
  it('computes chunk counts and ciphertext sizes, and omits optional fields when unused', async () => {
    const prepared = await prepareDrop({
      files: [textFile('a.txt', 'abc'), new File([], 'zero.bin')],
      note: '   ',
      expiresInHours: 6,
      maxDownloads: 2,
    });
    expect(prepared.request.files.map((f) => [f.chunkCount, f.ciphertextBytes])).toEqual([
      [1, 19],
      [1, 16],
    ]);
    expect(prepared.request).not.toHaveProperty('password');
    expect(prepared.request).not.toHaveProperty('ownerWrappedKey');
    expect((await decryptManifest(prepared.dk, prepared.request.encryptedManifest)).note).toBe(
      null,
    );
  });
});

describe('verifyResume (R11)', () => {
  async function statusFor(
    file: File,
    upTo: number,
  ): Promise<{ prepared: Awaited<ReturnType<typeof jobFor>>; status: UploadStatus }> {
    const prepared = await jobFor(file);
    const { requests } = capturingFetch();
    await uploadDropFiles({
      dropId: DROP_ID,
      uploadToken: TOKEN,
      dk: prepared.dk,
      files: prepared.files,
    });
    const job = prepared.files[0]!;
    const received = requests
      .map((r) => ({
        index: Number(r.url.split('/').at(-1)),
        sha256: r.headers.get('x-chunk-sha256')!,
      }))
      .filter((r) => r.index <= upTo);
    return {
      prepared,
      status: { files: [{ id: job.id, chunkCount: job.chunkCount, received }] },
    };
  }

  it('accepts the same file and reports the received chunks', async () => {
    const file = bytesFile('v.bin', CHUNK_SIZE * 2 + 1, (i) => (i * 7) % 256);
    const { prepared, status } = await statusFor(file, 1);
    const result = await verifyResume(prepared.dk, prepared.files, status);
    expect(result.ok).toBe(true);
    if (result.ok) expect([...result.received.get(prepared.files[0]!.id)!]).toEqual([0, 1]);
  });

  it('rejects a different file of the same size (re-encrypted last chunk hash mismatch)', async () => {
    const file = bytesFile('v.bin', CHUNK_SIZE * 2 + 1, (i) => (i * 7) % 256);
    const { prepared, status } = await statusFor(file, 1);
    const impostor = bytesFile('v.bin', CHUNK_SIZE * 2 + 1, (i) =>
      i === CHUNK_SIZE + 10 ? 0xff : (i * 7) % 256,
    );
    const result = await verifyResume(
      prepared.dk,
      [{ ...prepared.files[0]!, file: impostor }],
      status,
    );
    expect(result).toEqual({ ok: false, reason: 'mismatch' });
  });

  it('rejects unknown file ids and chunk-count changes, accepts files with nothing received', async () => {
    const prepared = await jobFor(textFile('a.txt', 'abc'));
    const job = prepared.files[0]!;
    const otherId = 'BBBBBBBBBBBBBBBBBBBBBA';
    expect(
      await verifyResume(prepared.dk, prepared.files, {
        files: [{ id: otherId, chunkCount: 1, received: [] }],
      }),
    ).toEqual({ ok: false, reason: 'mismatch' });
    expect(
      await verifyResume(prepared.dk, prepared.files, {
        files: [{ id: job.id, chunkCount: 2, received: [] }],
      }),
    ).toEqual({ ok: false, reason: 'mismatch' });
    const fresh = await verifyResume(prepared.dk, prepared.files, {
      files: [{ id: job.id, chunkCount: 1, received: [] }],
    });
    expect(fresh.ok).toBe(true);
  });
});

describe('retry helpers and worker error transport', () => {
  it('retryDelayFor takes the larger of the backoff and Retry-After, capped', () => {
    const rl = (s: number) =>
      new ApiError({ status: 429, code: 'RATE_LIMITED', message: 'x', retryAfter: s });
    expect(retryDelayFor(rl(1), 2000)).toBe(2000);
    expect(retryDelayFor(rl(30), 500)).toBe(30_000);
    expect(retryDelayFor(rl(100_000), 500)).toBe(120_000);
    expect(retryDelayFor(new Error('x'), 500)).toBe(500);
  });

  it('serialises errors to {code, message} and back', () => {
    const api = new ApiError({ status: 503, code: 'INTERNAL', message: 'down', retryAfter: 3 });
    const wire = serializeUploadError(api);
    expect(wire).toEqual({ code: 'INTERNAL', message: 'down', status: 503, retryAfter: 3 });
    const back = deserializeUploadError(structuredClone(wire));
    expect(back).toBeInstanceOf(ApiError);
    expect((back as ApiError).isRetryable).toBe(true);

    const abort = deserializeUploadError(
      serializeUploadError(new DOMException('stop', 'AbortError')),
    );
    expect((abort as Error).name).toBe('AbortError');

    const range = serializeUploadError(new RangeError('too long'));
    expect(range.code).toBe('UNKNOWN');
    // Unknown errors never leak their message (it could echo a file name).
    expect(range.message).not.toContain('too long');
    expect(generateDropKey()).toHaveLength(32);
  });
});
