import {
  b64urlDecode,
  b64urlEncode,
  createPasswordProtection,
  deriveDropPasswordKeys,
  deriveFileKey,
  encryptChunk,
  generateFileId,
  KDF_MIN,
  randomBytes,
} from '@cipherdrop/crypto';
import type { DropMeta } from '@cipherdrop/shared';
import { act, configure, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { prepareDrop } from '../../crypto/uploader';
import { queryClient } from '../../lib/queryClient';
import { routes } from '../../router';
import { useAuth } from '../../stores/auth';

vi.mock('../../crypto/kdfClient', () => ({
  kdfClient: {
    deriveAccountKeys: vi.fn(),
    createAccountBundle: vi.fn(),
    deriveDropPasswordKeys: vi.fn(),
    createPasswordProtection: vi.fn(),
  },
}));
const { kdfClient } = await import('../../crypto/kdfClient');

// The machine running these tests is shared and busy: give async queries room.
configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

const token = () => b64urlEncode(randomBytes(32));
const INTEGRITY = 'This file was modified in transit or storage. Download blocked.';

interface Fixture {
  dropId: string;
  dkB64: string;
  meta: DropMeta;
  chunks: Map<string, Uint8Array>;
}

async function fixture(
  opts: { remaining?: number; max?: number; note?: string | null; password?: string } = {},
): Promise<Fixture> {
  const content = new TextEncoder().encode('quarterly numbers: 42');
  const file = new File([content], 'report.bin', {
    type: 'application/octet-stream',
    lastModified: 1,
  });
  const prepared = await prepareDrop({
    files: [file],
    note: opts.note === undefined ? 'Here are the numbers' : opts.note,
    expiresInHours: 24,
    maxDownloads: 3,
  });
  const dropId = generateFileId();
  const chunks = new Map<string, Uint8Array>();
  for (const job of prepared.files) {
    // jsdom's File has no arrayBuffer() (R20): encrypt the known bytes directly (single chunk).
    const key = await deriveFileKey(prepared.dk, job.id);
    const ciphertext = await encryptChunk(key, 0, true, content);
    chunks.set(`/api/drops/${dropId}/files/${job.id}/chunks/0`, ciphertext);
  }
  const meta: DropMeta = {
    id: dropId,
    status: 'READY',
    fileCount: 1,
    totalBytes: prepared.files[0]!.ciphertextBytes,
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    maxDownloads: opts.max ?? 3,
    downloadsRemaining: opts.remaining ?? 2,
    passwordProtected: false,
    encryptedManifest: prepared.request.encryptedManifest,
    passwordKdf: null,
    createdAt: new Date().toISOString(),
  };
  return { dropId, dkB64: b64urlEncode(prepared.dk), meta, chunks };
}

type Handler = (url: URL, init: RequestInit) => Response | Promise<Response> | undefined;

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function mockApi(f: Fixture, extra?: Handler) {
  const calls: Array<{ method: string; path: string; body?: unknown }> = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), 'http://localhost');
    const method = init.method ?? 'GET';
    calls.push({
      method,
      path: url.pathname,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
    });
    const custom = extra ? await extra(url, init) : undefined;
    if (custom) return custom;
    if (method === 'GET' && url.pathname === `/api/drops/${f.dropId}`) return json(f.meta);
    if (method === 'POST' && url.pathname === `/api/drops/${f.dropId}/open`) {
      return json({
        downloadToken: token(),
        expiresAt: new Date(Date.now() + 600_000).toISOString(),
        downloadsRemaining: Math.max(0, f.meta.downloadsRemaining - 1),
      });
    }
    const chunk = f.chunks.get(url.pathname);
    if (method === 'GET' && chunk) return new Response(new Uint8Array(chunk), { status: 200 });
    return json({ error: { code: 'UNAUTHORIZED', message: 'no' } }, 401);
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(<RouterProvider router={router} />);
  return router;
}

// The route module loads lazily; load it once up front so the first tests don't race its transform.
beforeAll(async () => {
  await import('./ReceivePage');
}, 60_000);

beforeEach(() => {
  useAuth.setState({ status: 'anonymous' });
  URL.createObjectURL = vi.fn(() => 'blob:mock');
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  queryClient.clear();
  useAuth.setState(useAuth.getInitialState());
});

describe('ReceivePage', () => {
  it('missing or short key shows incomplete-link state', async () => {
    const f = await fixture();
    mockApi(f);
    renderAt(`/d/${f.dropId}`);
    expect(await screen.findByRole('heading', { name: 'This link is incomplete' })).toBeVisible();
    expect(screen.queryByRole('button', { name: /decrypt/i })).toBeNull();
  });

  it.each([
    ['a short key', (k: string) => k.slice(0, 30)],
    ['a key cut by one character', (k: string) => k.slice(0, 42)],
    ['a garbage fragment', () => '%%%not-a-key'],
  ])('%s shows the incomplete-link state, never a crash', async (_label, mangle) => {
    const f = await fixture();
    mockApi(f);
    renderAt(`/d/${f.dropId}#${mangle(f.dkB64)}`);
    expect(await screen.findByRole('heading', { name: 'This link is incomplete' })).toBeVisible();
  });

  it('a link with trailing chat punctuation still opens', async () => {
    const f = await fixture();
    mockApi(f);
    renderAt(`/d/${f.dropId}#${f.dkB64}).`);
    expect(await screen.findByText('report.bin')).toBeVisible();
  });

  it('unknown drop shows not found', async () => {
    const f = await fixture();
    mockApi(f, (url) =>
      url.pathname === `/api/drops/${f.dropId}`
        ? json({ error: { code: 'NOT_FOUND', message: 'Not found' } }, 404)
        : undefined,
    );
    renderAt(`/d/${f.dropId}#${f.dkB64}`);
    expect(await screen.findByRole('heading', { name: "This drop doesn't exist" })).toBeVisible();
  });

  it.each([
    ['EXPIRED', 'This drop has expired'],
    ['EXHAUSTED', 'All downloads have been used'],
    ['DELETED', 'This drop was deleted'],
    ['DISABLED', 'This drop was disabled'],
  ])('410 %s shows the reason-specific gone state', async (reason, title) => {
    const f = await fixture();
    mockApi(f, (url) =>
      url.pathname === `/api/drops/${f.dropId}`
        ? json({ error: { code: 'GONE', message: 'Gone', details: { reason } } }, 410)
        : undefined,
    );
    renderAt(`/d/${f.dropId}#${f.dkB64}`);
    expect(await screen.findByRole('heading', { name: title })).toBeVisible();
  });

  it('ready: decrypted note, file list and downloads left; download verifies and saves', async () => {
    const f = await fixture({ remaining: 2, max: 3 });
    const calls = mockApi(f);
    renderAt(`/d/${f.dropId}#${f.dkB64}`);
    expect(await screen.findByText('Here are the numbers')).toBeVisible();
    expect(screen.getByText('report.bin')).toBeVisible();
    expect(screen.getByText(/2 of 3 downloads left/)).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));
    const list = screen.getByRole('list', { name: 'Files in this drop' });
    expect(await within(list).findByText('Integrity verified')).toBeVisible();
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/1 of 3 downloads left/)).toBeVisible();
    // The open request carries no key material for a key link.
    expect(calls.find((c) => c.path.endsWith('/open'))?.body).toEqual({});
    // Nothing about the key or file names ever reaches a URL.
    for (const c of calls) {
      expect(c.path).not.toContain(f.dkB64);
      expect(c.path).not.toContain('report');
    }
  });

  it('a tampered chunk shows the integrity error and saves nothing', async () => {
    const f = await fixture();
    for (const [k, v] of f.chunks) {
      const t = new Uint8Array(v);
      t[0]! ^= 1;
      f.chunks.set(k, t);
    }
    mockApi(f);
    renderAt(`/d/${f.dropId}#${f.dkB64}`);
    await userEvent.click(await screen.findByRole('button', { name: /decrypt & download/i }));
    expect(await screen.findByText(INTEGRITY)).toBeVisible();
    expect(screen.getByText('Blocked')).toBeVisible();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it('a network failure is retryable and never shows the integrity error', async () => {
    const f = await fixture();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      mockApi(f, (url) => {
        if (url.pathname.includes('/chunks/')) throw new TypeError('Failed to fetch');
        return undefined;
      });
      renderAt(`/d/${f.dropId}#${f.dkB64}`);
      await userEvent.click(await screen.findByRole('button', { name: /decrypt & download/i }));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
      expect(await screen.findByRole('button', { name: 'Try again' })).toBeVisible();
      expect(screen.queryByText(INTEGRITY)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('asks for confirmation before consuming the last download', async () => {
    const f = await fixture({ remaining: 1, max: 1 });
    const calls = mockApi(f);
    renderAt(`/d/${f.dropId}#${f.dkB64}`);
    await userEvent.click(await screen.findByRole('button', { name: /decrypt & download/i }));
    const dialog = await screen.findByRole('dialog', { name: 'This is the last download' });
    expect(calls.some((c) => c.path.endsWith('/open'))).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Download now' }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith('/open'))).toBe(true));
    expect((await screen.findAllByText('Integrity verified')).length).toBeGreaterThan(0);
  });

  it('an expired grant with no downloads left shows "download window expired" (R12)', async () => {
    const f = await fixture({ remaining: 2 });
    let metaCalls = 0;
    mockApi(f, (url) => {
      if (url.pathname === `/api/drops/${f.dropId}`) {
        metaCalls++;
        return json({ ...f.meta, downloadsRemaining: metaCalls === 1 ? 2 : 0 });
      }
      if (url.pathname.includes('/chunks/'))
        return json({ error: { code: 'UNAUTHORIZED', message: 'expired' } }, 401);
      return undefined;
    });
    renderAt(`/d/${f.dropId}#${f.dkB64}`);
    await userEvent.click(await screen.findByRole('button', { name: /decrypt & download/i }));
    expect(
      await screen.findByRole('heading', { name: 'Your download window expired' }),
    ).toBeVisible();
    expect(screen.queryByText(INTEGRITY)).toBeNull();
  });

  describe('password drops', () => {
    async function passwordFixture() {
      const f = await fixture();
      const original = f.meta.encryptedManifest!;
      const protection = await createPasswordProtection(
        b64urlDecode(f.dkB64),
        'right password',
        KDF_MIN,
      );
      const keys = await deriveDropPasswordKeys('right password', protection.kdf);
      f.meta = {
        ...f.meta,
        passwordProtected: true,
        passwordKdf: protection.kdf,
        encryptedManifest: null,
      };
      return { f, protection, keys, original };
    }

    it('wrong password shakes and shows a message; rate limit shows the wait', async () => {
      const { f, keys } = await passwordFixture();
      vi.mocked(kdfClient.deriveDropPasswordKeys).mockResolvedValue(keys);
      let attempt = 0;
      mockApi(f, (url) => {
        if (url.pathname.endsWith('/unlock')) {
          attempt++;
          return attempt === 1
            ? json({ error: { code: 'UNAUTHORIZED', message: 'Wrong password' } }, 401)
            : json({ error: { code: 'RATE_LIMITED', message: 'Too many' } }, 429, {
                'retry-after': '900',
              });
        }
        return undefined;
      });
      renderAt(`/d/${f.dropId}`);
      const input = await screen.findByLabelText('Password');
      await userEvent.type(input, 'nope');
      await userEvent.click(screen.getByRole('button', { name: 'Unlock' }));
      expect(await screen.findByText(/Wrong password/)).toBeVisible();
      await userEvent.click(screen.getByRole('button', { name: 'Unlock' }));
      expect(await screen.findByText('Too many attempts. Try again in 15 min.')).toBeVisible();
    });

    it('right password unlocks locally and opens with the authKey', async () => {
      const { f, keys, protection, original } = await passwordFixture();
      vi.mocked(kdfClient.deriveDropPasswordKeys).mockResolvedValue(keys);
      const calls = mockApi(f, (url) =>
        url.pathname.endsWith('/unlock')
          ? json({ wrappedDropKey: protection.wrappedDropKey, encryptedManifest: original })
          : undefined,
      );
      renderAt(`/d/${f.dropId}`);
      await userEvent.type(await screen.findByLabelText('Password'), 'right password');
      await userEvent.click(screen.getByRole('button', { name: 'Unlock' }));
      expect(await screen.findByText('report.bin')).toBeVisible();
      await userEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));
      await waitFor(() => expect(calls.some((c) => c.path.endsWith('/open'))).toBe(true));
      const authKey = b64urlEncode(keys.authKey);
      expect(calls.find((c) => c.path.endsWith('/unlock'))?.body).toEqual({ authKey });
      expect(calls.find((c) => c.path.endsWith('/open'))?.body).toEqual({ authKey });
      // The password itself never leaves the page.
      expect(JSON.stringify(calls)).not.toContain('right password');
    });
  });
});
