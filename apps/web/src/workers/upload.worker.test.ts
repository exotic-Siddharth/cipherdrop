// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { prepareDrop } from '../crypto/uploader';
import { createUploadWorkerHandler, type UploadWorkerResponse } from './upload.worker';

const DROP_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
const TOKEN = 'U'.repeat(43);

async function setup(names: string[]) {
  const files = names.map((n) => new File([`content of ${n}`], n, { lastModified: 1 }));
  return prepareDrop({ files, note: null, expiresInHours: 1, maxDownloads: 1 });
}

function collect() {
  const out: UploadWorkerResponse[] = [];
  let resolveEnd: () => void = () => undefined;
  const ended = new Promise<void>((r) => (resolveEnd = r));
  const post = (m: UploadWorkerResponse) => {
    // Everything the worker posts must survive structured clone.
    out.push(structuredClone(m));
    if (m.type === 'done' || m.type === 'error') resolveEnd();
  };
  return { out, post, ended };
}

describe('upload.worker message protocol', () => {
  it('posts progress events then done', async () => {
    const prepared = await setup(['a.txt', 'b.txt']);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 204 })),
    );
    const { out, post, ended } = collect();
    const handle = createUploadWorkerHandler(post);
    handle({
      type: 'start',
      job: {
        dropId: DROP_ID,
        uploadToken: TOKEN,
        dk: prepared.dk,
        files: prepared.files,
        baseUrl: 'http://localhost:5195',
      },
    });
    await ended;
    expect(out.at(-1)).toEqual({ type: 'done' });
    const types = out.map((m) => (m.type === 'event' ? m.event.type : m.type));
    expect(types.filter((t) => t === 'file-done')).toHaveLength(2);
    expect(types).toContain('cipher-preview');
    const preview = out.find((m) => m.type === 'event' && m.event.type === 'cipher-preview');
    expect(
      preview?.type === 'event' && preview.event.type === 'cipher-preview' && preview.event.hex,
    ).toMatch(/^[0-9a-f]+$/);
  });

  it('reports a fatal error as a plain {code, message} object', async () => {
    const prepared = await setup(['a.txt']);
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'bad token' } }), {
            status: 401,
          }),
      ),
    );
    const { out, post, ended } = collect();
    createUploadWorkerHandler(post)({
      type: 'start',
      job: {
        dropId: DROP_ID,
        uploadToken: TOKEN,
        dk: prepared.dk,
        files: prepared.files,
        baseUrl: 'http://localhost:5195',
      },
    });
    await ended;
    expect(out.at(-1)).toEqual({
      type: 'error',
      error: { code: 'UNAUTHORIZED', message: 'bad token', status: 401 },
    });
  });

  it('cancel aborts in-flight PUTs and ends with ABORTED', async () => {
    const prepared = await setup(['a.txt', 'b.txt', 'c.txt', 'd.txt']);
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init.signal?.addEventListener('abort', () =>
              reject(new DOMException('aborted', 'AbortError')),
            );
          }),
      ),
    );
    const { out, post, ended } = collect();
    const handle = createUploadWorkerHandler(post);
    handle({
      type: 'start',
      job: {
        dropId: DROP_ID,
        uploadToken: TOKEN,
        dk: prepared.dk,
        files: prepared.files,
        baseUrl: 'http://localhost:5195',
      },
    });
    await vi.waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(3));
    handle({ type: 'cancel' });
    await ended;
    expect(out.at(-1)).toEqual({
      type: 'error',
      error: { code: 'ABORTED', message: 'Upload cancelled.' },
    });
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(3);
  });
});
