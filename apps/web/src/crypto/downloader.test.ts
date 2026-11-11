// @vitest-environment node
import { CHUNK_SIZE, decryptManifest, IntegrityError, type ManifestFile } from '@cipherdrop/crypto';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../lib/http';
import { DownloadSession, GrantExpiredError, type DownloadGrant } from './downloader';
import { createBlobSink, type FileSink } from './sinks';
import { prepareDrop, uploadDropFiles } from './uploader';

const DROP_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
const GRANT: DownloadGrant = {
  downloadToken: 'D'.repeat(43),
  expiresAt: '2026-11-08T12:00:00.000Z',
  downloadsRemaining: 0,
};

/** Encrypt `files` with the real pipeline and keep the ciphertext chunks as a fake server would. */
async function encryptedDrop(files: File[]) {
  const prepared = await prepareDrop({ files, note: 'hi', expiresInHours: 1, maxDownloads: 1 });
  const store = new Map<string, Uint8Array>();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      store.set(new URL(url, 'http://x').pathname, new Uint8Array(init.body as Uint8Array));
      return new Response(null, { status: 204 });
    }),
  );
  await uploadDropFiles({
    dropId: DROP_ID,
    uploadToken: 'U'.repeat(43),
    dk: prepared.dk,
    files: prepared.files,
  });
  vi.unstubAllGlobals();
  const manifest = await decryptManifest(prepared.dk, prepared.request.encryptedManifest);
  return { dk: prepared.dk, manifest, store };
}

type Responder = (path: string, n: number, init: RequestInit) => Response | Promise<Response>;

function serve(store: Map<string, Uint8Array>, override?: Responder) {
  let n = 0;
  const fn = vi.fn(async (url: string, init: RequestInit) => {
    n++;
    const path = new URL(url, 'http://x').pathname;
    const custom = override ? await override(path, n, init) : undefined;
    if (custom) return custom;
    const body = store.get(path);
    return body
      ? new Response(new Uint8Array(body), { status: 200 })
      : new Response(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'no' } }), {
          status: 404,
        });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function spySink(): FileSink & { writes: number; closed: boolean; aborted: boolean } {
  const inner = createBlobSink('application/octet-stream');
  const spy = {
    kind: 'blob' as const,
    writes: 0,
    closed: false,
    aborted: false,
    async write(c: Uint8Array) {
      spy.writes++;
      await inner.write(c);
    },
    async close() {
      spy.closed = true;
      return inner.close();
    },
    async abort() {
      spy.aborted = true;
      await inner.abort();
    },
  };
  return spy;
}

const recordSleep = () => {
  const delays: number[] = [];
  return { delays, sleep: async (ms: number) => void delays.push(ms) };
};

const text = (name: string, s: string) =>
  new File([s], name, { type: 'text/plain', lastModified: 1 });

describe('DownloadSession', () => {
  it('downloads, verifies and decrypts every file with one grant', async () => {
    const big = new Uint8Array(CHUNK_SIZE + 77).map((_, i) => i % 199);
    const { dk, manifest, store } = await encryptedDrop([
      text('a.txt', 'alpha'),
      new File([big], 'big.bin', { lastModified: 2 }),
      new File([], 'empty.txt', { lastModified: 3 }),
    ]);
    const fetchFn = serve(store);
    const open = vi.fn(async () => GRANT);
    const session = new DownloadSession({ dropId: DROP_ID, dk, open });

    const blobs: Blob[] = [];
    for (const f of manifest.files) {
      const blob = await session.downloadFile(f, createBlobSink(f.type));
      blobs.push(blob!);
    }
    expect(open).toHaveBeenCalledTimes(1);
    expect(await blobs[0]!.text()).toBe('alpha');
    expect(blobs[0]!.type).toBe('text/plain');
    expect(Buffer.from(await blobs[1]!.arrayBuffer()).equals(Buffer.from(big))).toBe(true);
    expect(blobs[2]!.size).toBe(0);
    expect(fetchFn).toHaveBeenCalledTimes(4);
    const auth = new Headers(fetchFn.mock.calls[0]![1].headers).get('authorization');
    expect(auth).toBe(`Bearer ${GRANT.downloadToken}`);
  });

  it('tampered chunk raises IntegrityError and writes nothing', async () => {
    const { dk, manifest, store } = await encryptedDrop([text('a.txt', 'do not trust me')]);
    const file = manifest.files[0]!;
    const path = `/api/drops/${DROP_ID}/files/${file.id}/chunks/0`;
    const tampered = new Uint8Array(store.get(path)!);
    tampered[3]! ^= 0x01;
    store.set(path, tampered);
    serve(store);
    const session = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT });
    const sink = spySink();
    const err = await session.downloadFile(file, sink).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IntegrityError);
    expect(sink.writes).toBe(0);
    expect(sink.closed).toBe(false);
    expect(sink.aborted).toBe(true);
  });

  it('a tampered final chunk aborts the sink: no file is produced', async () => {
    const big = new Uint8Array(CHUNK_SIZE + 10).fill(7);
    const { dk, manifest, store } = await encryptedDrop([new File([big], 'b.bin')]);
    const file = manifest.files[0]!;
    const path = `/api/drops/${DROP_ID}/files/${file.id}/chunks/1`;
    const tampered = new Uint8Array(store.get(path)!);
    tampered[tampered.length - 1]! ^= 0x80;
    store.set(path, tampered);
    serve(store);
    const session = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT });
    const sink = spySink();
    await expect(session.downloadFile(file, sink)).rejects.toBeInstanceOf(IntegrityError);
    expect(sink.closed).toBe(false);
    expect(sink.aborted).toBe(true);
  });

  it('swapped chunks and a truncated chunk are integrity failures', async () => {
    const big = new Uint8Array(CHUNK_SIZE * 2).map((_, i) => i % 13);
    const { dk, manifest, store } = await encryptedDrop([new File([big], 'b.bin')]);
    const file = manifest.files[0]!;
    const p = (i: number) => `/api/drops/${DROP_ID}/files/${file.id}/chunks/${i}`;
    const [c0, c1] = [store.get(p(0))!, store.get(p(1))!];
    const swapped = new Map(store);
    swapped.set(p(0), c1);
    swapped.set(p(1), c0);
    serve(swapped);
    const s1 = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT });
    await expect(s1.downloadFile(file, spySink())).rejects.toBeInstanceOf(IntegrityError);

    const truncated = new Map(store);
    truncated.set(p(1), c1.slice(0, c1.length - 100));
    serve(truncated);
    const s2 = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT });
    await expect(s2.downloadFile(file, spySink())).rejects.toBeInstanceOf(IntegrityError);
  });

  it('retries a chunk GET that fails once', async () => {
    const { dk, manifest, store } = await encryptedDrop([text('a.txt', 'flaky')]);
    const fetchFn = serve(
      store,
      (_p, n) => (n === 1 ? new Response(null, { status: 502 }) : undefined) as Response,
    );
    const { delays, sleep } = recordSleep();
    const session = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT, sleep });
    const blob = await session.downloadFile(manifest.files[0]!, createBlobSink('text/plain'));
    expect(await blob!.text()).toBe('flaky');
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(delays).toEqual([500]);
  });

  it('network errors: 3 attempts, then a retryable ApiError (never the integrity error)', async () => {
    const { dk, manifest, store } = await encryptedDrop([text('a.txt', 'x')]);
    const fetchFn = serve(store, () => {
      throw new TypeError('Failed to fetch');
    });
    const { delays, sleep } = recordSleep();
    const session = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT, sleep });
    const sink = spySink();
    const err = await session.downloadFile(manifest.files[0]!, sink).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe('NETWORK_ERROR');
    expect((err as ApiError).isRetryable).toBe(true);
    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(delays).toEqual([500, 2000]);
    expect(sink.aborted).toBe(true);
  });

  it('honours Retry-After on 429', async () => {
    const { dk, manifest, store } = await encryptedDrop([text('a.txt', 'x')]);
    serve(
      store,
      (_p, n) =>
        (n === 1
          ? new Response(
              JSON.stringify({ error: { code: 'RATE_LIMITED', message: 'slow down' } }),
              {
                status: 429,
                headers: { 'Retry-After': '12' },
              },
            )
          : undefined) as Response,
    );
    const { delays, sleep } = recordSleep();
    const session = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT, sleep });
    await session.downloadFile(manifest.files[0]!, createBlobSink('text/plain'));
    expect(delays).toEqual([12_000]);
  });

  it('an expired grant (401) stops without re-opening until the user confirms (R12)', async () => {
    const { dk, manifest, store } = await encryptedDrop([
      text('a.txt', 'one'),
      text('b.txt', 'two'),
    ]);
    let expire = true;
    serve(
      store,
      () =>
        (expire
          ? new Response(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'expired' } }), {
              status: 401,
            })
          : undefined) as Response,
    );
    const open = vi.fn(async () => GRANT);
    const { delays, sleep } = recordSleep();
    const session = new DownloadSession({ dropId: DROP_ID, dk, open, sleep });
    await expect(session.downloadFile(manifest.files[0]!, spySink())).rejects.toBeInstanceOf(
      GrantExpiredError,
    );
    expect(delays).toEqual([]);
    expect(session.hasExpired).toBe(true);
    // Next file: still no silent re-open.
    await expect(session.downloadFile(manifest.files[1]!, spySink())).rejects.toBeInstanceOf(
      GrantExpiredError,
    );
    expect(open).toHaveBeenCalledTimes(1);
    // Confirmed re-open.
    expire = false;
    await session.open();
    expect(open).toHaveBeenCalledTimes(2);
    const blob = await session.downloadFile(manifest.files[1]!, createBlobSink('text/plain'));
    expect(await blob!.text()).toBe('two');
  });

  it('starts from a provided grant (admin review) without calling open', async () => {
    const { dk, manifest, store } = await encryptedDrop([text('a.txt', 'review')]);
    serve(store);
    const open = vi.fn(async () => GRANT);
    const session = new DownloadSession({ dropId: DROP_ID, dk, open, grant: GRANT });
    const f: ManifestFile = manifest.files[0]!;
    expect(await (await session.downloadFile(f, createBlobSink(f.type)))!.text()).toBe('review');
    expect(open).not.toHaveBeenCalled();
  });

  it('cancel aborts the file', async () => {
    const { dk, manifest, store } = await encryptedDrop([text('a.txt', 'x')]);
    serve(store);
    const ctrl = new AbortController();
    ctrl.abort();
    const session = new DownloadSession({ dropId: DROP_ID, dk, open: async () => GRANT });
    const sink = spySink();
    const err = await session
      .downloadFile(manifest.files[0]!, sink, { signal: ctrl.signal })
      .catch((e: unknown) => e);
    expect((err as Error).name).toBe('AbortError');
    expect(sink.aborted).toBe(true);
  });
});
