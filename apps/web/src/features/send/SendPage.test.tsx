import { b64urlEncode, generateFileId, importAesKey, randomBytes } from '@cipherdrop/crypto';
import type { Me } from '@cipherdrop/shared';
import { act, configure, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { UploadWorkerJob } from '../../workers/upload.worker';
import { queryClient } from '../../lib/queryClient';
import { routes } from '../../router';
import { useAuth } from '../../stores/auth';
import { readDeviceDrops, useDeviceDrops } from '../../stores/deviceDrops';
import { useVault } from '../../stores/vault';
import { readResumeRecord, RESUME_STORAGE_KEY, writeResumeRecord } from './resumeRecord';

vi.mock('./uploadClient', () => ({
  runUploadInWorker: vi.fn(async (job: UploadWorkerJob, onEvent: (e: unknown) => void) => {
    for (const f of job.files) {
      onEvent({ type: 'cipher-preview', fileId: f.id, index: 0, hex: 'ab'.repeat(48) });
      onEvent({ type: 'chunk-encrypted', fileId: f.id, index: 0, plainBytes: f.file.size });
      onEvent({ type: 'chunk-uploaded', fileId: f.id, index: 0, plainBytes: f.file.size });
      onEvent({ type: 'file-done', fileId: f.id });
    }
  }),
}));
const { runUploadInWorker } = await import('./uploadClient');

configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

const token = () => b64urlEncode(randomBytes(32));
const SECRET_NAME = 'merger-plans-confidential.txt';

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function mockApi(extra?: (path: string, method: string) => Response | undefined) {
  const calls: Array<{ method: string; path: string; body: string | null; headers: Headers }> = [];
  const dropId = generateFileId();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = new URL(String(input), 'http://localhost');
      const method = init.method ?? 'GET';
      calls.push({
        method,
        path: url.pathname,
        body: typeof init.body === 'string' ? init.body : null,
        headers: new Headers(init.headers),
      });
      const custom = extra?.(url.pathname, method);
      if (custom) return custom;
      if (method === 'POST' && url.pathname === '/api/drops') {
        return json(
          {
            dropId,
            ownerToken: token(),
            uploadToken: token(),
            expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
          },
          201,
        );
      }
      if (method === 'POST' && url.pathname.endsWith('/complete')) return json({ status: 'READY' });
      if (method === 'DELETE') return new Response(null, { status: 204 });
      return json({ error: { code: 'UNAUTHORIZED', message: 'no' } }, 401);
    }),
  );
  return { calls, dropId };
}

function renderSend() {
  const router = createMemoryRouter(routes, { initialEntries: ['/'] });
  render(<RouterProvider router={router} />);
  return router;
}

/** An upload that never finishes until it is aborted. */
function hangingUpload() {
  vi.mocked(runUploadInWorker).mockImplementationOnce(
    (_job, _onEvent, signal) =>
      new Promise<void>((_resolve, reject) => {
        signal?.addEventListener('abort', () =>
          reject(new DOMException('The operation was aborted.', 'AbortError')),
        );
      }),
  );
}

/** An upload that the test finishes or fails by hand. */
function controlledUpload() {
  const handle: { finish?: () => void; fail?: (err: unknown) => void } = {};
  vi.mocked(runUploadInWorker).mockImplementationOnce(
    () =>
      new Promise<void>((resolve, reject) => {
        handle.finish = resolve;
        handle.fail = reject;
      }),
  );
  return {
    finish: async () => {
      await waitFor(() => expect(handle.finish).toBeDefined());
      handle.finish!();
    },
    fail: async () => {
      await waitFor(() => expect(handle.fail).toBeDefined());
      handle.fail!(Object.assign(new Error('x'), { code: 'NETWORK_ERROR' }));
    },
  };
}

const networkError = () => Object.assign(new Error('x'), { code: 'NETWORK_ERROR' });

async function addFile(file: File) {
  const input = await screen.findByTestId('file-input');
  await userEvent.upload(input as HTMLInputElement, file);
}

const user: Me = {
  id: 'user_1',
  email: 'ada@example.com',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 5 * 1024 ** 3,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
};

beforeAll(async () => {
  await import('./SendPage');
}, 60_000);

beforeEach(() => {
  useAuth.setState({ status: 'anonymous' });
  window.localStorage.clear();
  window.sessionStorage.clear();
  useDeviceDrops.setState({ drops: [] });
  vi.mocked(runUploadInWorker).mockClear();
});

afterEach(() => {
  queryClient.clear();
  useAuth.setState(useAuth.getInitialState());
  useVault.setState(useVault.getInitialState());
});

describe('SendPage', () => {
  it('anonymous: encrypts, uploads, shows the key link and remembers the drop on this device', async () => {
    const { calls, dropId } = mockApi();
    renderSend();
    await addFile(new File(['top secret'], SECRET_NAME, { type: 'text/plain' }));
    expect(await screen.findByText(SECRET_NAME)).toBeVisible();
    await userEvent.type(screen.getByLabelText(/Note for the recipient/), 'see you at noon');
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));

    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    const link = (screen.getByLabelText('Share link') as HTMLInputElement).value;
    expect(link).toMatch(new RegExp(`/d/${dropId}#[A-Za-z0-9_-]{43}$`));
    expect(
      screen.getByText(
        'The key after # never reaches our server. Anyone with the full link can download.',
      ),
    ).toBeVisible();

    // The create request carries no plaintext metadata and no key.
    const create = calls.find((c) => c.method === 'POST' && c.path === '/api/drops')!;
    expect(create.body).not.toContain('merger');
    expect(create.body).not.toContain('see you at noon');
    expect(create.body).not.toContain(link.split('#')[1]);
    expect(create.headers.get('authorization')).toBeNull();
    expect(calls.some((c) => c.path === `/api/drops/${dropId}/complete`)).toBe(true);

    // Remembered on this device without names or keys; the resume record is gone.
    expect(readDeviceDrops().map((d) => d.dropId)).toEqual([dropId]);
    expect(window.localStorage.getItem('cd-device-drops')).not.toContain('merger');
    expect(window.sessionStorage.getItem(RESUME_STORAGE_KEY)).toBeNull();
    expect(screen.getByRole('heading', { name: 'Sent from this device' })).toBeVisible();
  });

  it('signed in with a locked vault: inline unlock blocks Encrypt & upload (R7)', async () => {
    mockApi();
    useAuth.setState({ status: 'authenticated', user, accessToken: 'access' });
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    expect(await screen.findByText('Your vault is locked')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Encrypt & upload' })).toBeDisabled();
    expect(screen.getByLabelText('Expires after')).toHaveTextContent('30 days');
  });

  it('Try again after the vault auto-locked asks to unlock instead of re-sending without an owner wrap (C-38)', async () => {
    let creates = 0;
    const { calls } = mockApi((path, method) => {
      if (method === 'POST' && path === '/api/drops' && ++creates === 1) {
        return json({ error: { code: 'INTERNAL', message: 'boom' } }, 500);
      }
      return undefined;
    });
    useAuth.setState({ status: 'authenticated', user, accessToken: 'access' });
    useVault.getState().setAccountKey(await importAesKey(randomBytes(32)));
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    act(() => useVault.getState().lock('idle'));
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Your vault is locked')).toBeVisible();
    expect(calls.filter((c) => c.method === 'POST' && c.path === '/api/drops')).toHaveLength(1);
  });

  it('a password without text blocks the upload', async () => {
    mockApi();
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('switch', { name: /Protect with a password/ }));
    expect(screen.getByRole('button', { name: 'Encrypt & upload' })).toBeDisabled();
    expect(screen.getByText(/Enter a password/)).toBeVisible();
  });

  it('a weak or short drop password blocks the upload (C-20)', async () => {
    mockApi();
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('switch', { name: /Protect with a password/ }));
    await userEvent.type(screen.getByLabelText('Password'), '1');
    expect(screen.getByRole('button', { name: 'Encrypt & upload' })).toBeDisabled();
    expect(screen.getByText(/Use at least 10 characters/)).toBeVisible();
    await userEvent.clear(screen.getByLabelText('Password'));
    await userEvent.type(screen.getByLabelText('Password'), 'password123');
    expect(await screen.findByText(/too easy to guess/)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Encrypt & upload' })).toBeDisabled();
    await userEvent.clear(screen.getByLabelText('Password'));
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery staple');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Encrypt & upload' })).toBeEnabled(),
    );
  });

  it('leaving the page mid-upload asks first and keeps the upload running on Stay (C-17)', async () => {
    mockApi();
    hangingUpload();
    const router = renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('Encrypting and uploading')).toBeVisible();

    await userEvent.click(screen.getAllByRole('link', { name: 'How it works' })[0]!);
    const dialog = await screen.findByRole('dialog', { name: /Leave and cancel the upload/ });
    expect(router.state.location.pathname).toBe('/');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep uploading' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(router.state.location.pathname).toBe('/');
    expect(screen.getByText('Encrypting and uploading')).toBeVisible();

    await userEvent.click(screen.getAllByRole('link', { name: 'How it works' })[0]!);
    const again = await screen.findByRole('dialog', { name: /Leave and cancel the upload/ });
    await userEvent.click(within(again).getByRole('button', { name: 'Leave' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/how-it-works'));
  });

  it('moves focus to the result and keeps one live region across view changes (C-23)', async () => {
    mockApi();
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    const region = screen.getByTestId('send-status');
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    const heading = await screen.findByRole('heading', { name: 'Your encrypted link is ready' });
    expect(heading).toHaveFocus();
    expect(screen.getByTestId('send-status')).toBe(region);
    expect(region).toHaveTextContent('Upload finished');
    expect(region).toHaveAttribute('aria-live', 'polite');
  });

  it('moves focus to the error notice when the upload fails (C-23)', async () => {
    mockApi();
    vi.mocked(runUploadInWorker).mockRejectedValueOnce(
      Object.assign(new Error('x'), { code: 'NETWORK_ERROR' }),
    );
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    const title = await screen.findByText('The upload did not finish');
    await waitFor(() => expect(title.closest('[tabindex="-1"]')).toHaveFocus());
  });

  it('resume after reload: matching files resume the same drop (R11)', async () => {
    const dropId = generateFileId();
    const fileId = generateFileId();
    const file = new File(['resume me'], 'r.txt', { lastModified: 1234 });
    writeResumeRecord({
      dropId,
      uploadToken: token(),
      dk: b64urlEncode(randomBytes(32)),
      files: [{ id: fileId, size: file.size, lastModified: 1234, chunkCount: 1 }],
      ownerToken: token(),
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      createdAt: new Date().toISOString(),
      maxDownloads: 1,
      passwordProtected: false,
      anonymous: true,
    });
    const { calls } = mockApi((path, method) =>
      method === 'GET' && path === `/api/drops/${dropId}/upload-status`
        ? json({ files: [{ id: fileId, chunkCount: 1, received: [] }] })
        : undefined,
    );
    renderSend();
    expect(await screen.findByText('An upload in this tab was interrupted')).toBeVisible();
    await addFile(file);
    await userEvent.click(await screen.findByRole('button', { name: 'Resume upload' }));
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    expect(calls.some((c) => c.method === 'POST' && c.path === '/api/drops')).toBe(false);
    const job = vi.mocked(runUploadInWorker).mock.calls[0]![0];
    expect(job.dropId).toBe(dropId);
    expect(job.files[0]!.id).toBe(fileId);
    expect(readResumeRecord()).toBeNull();
  });

  it('resume mismatch (drop no longer uploading) abandons it and starts a fresh drop', async () => {
    const oldDrop = generateFileId();
    const ownerToken = token();
    const file = new File(['resume me'], 'r.txt', { lastModified: 99 });
    writeResumeRecord({
      dropId: oldDrop,
      uploadToken: token(),
      dk: b64urlEncode(randomBytes(32)),
      files: [{ id: generateFileId(), size: file.size, lastModified: 99, chunkCount: 1 }],
      ownerToken,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      createdAt: new Date().toISOString(),
      maxDownloads: 1,
      passwordProtected: false,
      anonymous: true,
    });
    const { calls, dropId } = mockApi((path, method) =>
      method === 'GET' && path === `/api/drops/${oldDrop}/upload-status`
        ? json({ error: { code: 'NOT_FOUND', message: 'gone' } }, 404)
        : undefined,
    );
    renderSend();
    await addFile(file);
    await userEvent.click(await screen.findByRole('button', { name: 'Resume upload' }));
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.path === '/api/drops')).toBe(true),
    );
    expect(vi.mocked(runUploadInWorker).mock.calls.at(-1)![0].dropId).toBe(dropId);
    // C-35: the abandoned UPLOADING drop is deleted best-effort with its owner token.
    const del = calls.find((c) => c.method === 'DELETE' && c.path === `/api/drops/${oldDrop}`);
    expect(del).toBeDefined();
    expect(del!.headers.get('x-owner-token')).toBe(ownerToken);
  });

  it('a new drop over an unmatched resume record deletes the old drop (C-35)', async () => {
    const oldDrop = generateFileId();
    const ownerToken = token();
    writeResumeRecord({
      dropId: oldDrop,
      uploadToken: token(),
      dk: b64urlEncode(randomBytes(32)),
      files: [{ id: generateFileId(), size: 9, lastModified: 99, chunkCount: 1 }],
      ownerToken,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      createdAt: new Date().toISOString(),
      maxDownloads: 1,
      passwordProtected: false,
      anonymous: true,
    });
    const { calls } = mockApi();
    renderSend();
    await addFile(new File(['something else entirely'], 'other.txt', { lastModified: 5 }));
    await userEvent.click(await screen.findByRole('button', { name: 'Encrypt & upload' }));
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    const del = calls.find((c) => c.method === 'DELETE' && c.path === `/api/drops/${oldDrop}`);
    expect(del).toBeDefined();
    expect(del!.headers.get('x-owner-token')).toBe(ownerToken);
  });

  it('Try again with changed files deletes the earlier drop before a new one (C-35)', async () => {
    const { calls, dropId } = mockApi();
    vi.mocked(runUploadInWorker).mockRejectedValueOnce(
      Object.assign(new Error('x'), { code: 'NETWORK_ERROR' }),
    );
    renderSend();
    await addFile(new File(['x'], 'a.txt', { lastModified: 1 }));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    await addFile(new File(['y'], 'b.txt', { lastModified: 2 }));
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE' && c.path === `/api/drops/${dropId}`)).toBe(
      true,
    );
  });

  it('a failed upload shows a retryable error state', async () => {
    mockApi();
    vi.mocked(runUploadInWorker).mockRejectedValueOnce(
      Object.assign(new Error('x'), { code: 'NETWORK_ERROR' }),
    );
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeEnabled();
  });

  it.each(['finishes', 'fails'] as const)(
    'a leave dialog open when the upload %s is dropped and does not reopen on the next upload (C-17)',
    async (outcome) => {
      mockApi();
      const upload = controlledUpload();
      const router = renderSend();
      await addFile(new File(['x'], 'a.txt'));
      await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
      await userEvent.click(screen.getAllByRole('link', { name: 'How it works' })[0]!);
      expect(
        await screen.findByRole('dialog', { name: /Leave and cancel the upload/ }),
      ).toBeVisible();

      if (outcome === 'finishes') {
        await upload.finish();
        await userEvent.click(await screen.findByRole('button', { name: 'Send another' }));
        await addFile(new File(['y'], 'b.txt'));
        hangingUpload();
        await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
      } else {
        await upload.fail();
        expect(await screen.findByText('The upload did not finish')).toBeVisible();
        hangingUpload();
        await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
      }
      await waitFor(() => expect(runUploadInWorker).toHaveBeenCalledTimes(2));
      expect(screen.getByText('Encrypting and uploading')).toBeVisible();
      expect(screen.queryByRole('dialog')).toBeNull();
      expect(router.state.location.pathname).toBe('/');
    },
  );

  it('the Send link and the logo while uploading stay on the page without asking (C-17)', async () => {
    mockApi();
    hangingUpload();
    const router = renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    await waitFor(() => expect(runUploadInWorker).toHaveBeenCalledTimes(1));
    await userEvent.click(screen.getAllByRole('link', { name: 'Send' })[0]!);
    await userEvent.click(screen.getByRole('link', { name: 'CipherDrop home' }));
    await act(async () => {});
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(router.state.location.pathname).toBe('/');
    expect(screen.getByText('Encrypting and uploading')).toBeVisible();
    expect(vi.mocked(runUploadInWorker).mock.calls[0]![2]!.aborted).toBe(false);
  });

  it('Sign out while uploading asks first: Stay keeps the session and the upload, Sign out cancels first (C-17)', async () => {
    const { calls, dropId } = mockApi();
    useAuth.setState({ status: 'authenticated', user, accessToken: 'access' });
    useVault.getState().setAccountKey(await importAesKey(randomBytes(32)));
    hangingUpload();
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    await waitFor(() => expect(runUploadInWorker).toHaveBeenCalledTimes(1));
    const signOut = async () => {
      await userEvent.click(screen.getByRole('button', { name: /ada@example.com account menu/ }));
      await userEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }));
      return screen.findByRole('dialog', { name: /Sign out and cancel the upload/ });
    };

    const dialog = await signOut();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep uploading' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await act(async () => {});
    expect(useAuth.getState().status).toBe('authenticated');
    expect(calls.some((c) => c.path === '/api/auth/logout')).toBe(false);
    expect(screen.getByText('Encrypting and uploading')).toBeVisible();
    expect(vi.mocked(runUploadInWorker).mock.calls[0]![2]!.aborted).toBe(false);

    const again = await signOut();
    await userEvent.click(within(again).getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(useAuth.getState().status).toBe('anonymous'));
    const del = calls.findIndex((c) => c.method === 'DELETE' && c.path === `/api/drops/${dropId}`);
    const logout = calls.findIndex((c) => c.path === '/api/auth/logout');
    expect(del).toBeGreaterThanOrEqual(0);
    expect(logout).toBeGreaterThan(del);
    expect(vi.mocked(runUploadInWorker).mock.calls[0]![2]!.aborted).toBe(true);
  });

  it('after Dismiss, the same files resume the failed drop instead of creating a second one (C-35)', async () => {
    let job: UploadWorkerJob | undefined;
    const { calls, dropId } = mockApi((path, method) =>
      method === 'GET' && path === `/api/drops/${path.split('/')[3]}/upload-status` && job
        ? json({
            files: job.files.map((f) => ({ id: f.id, chunkCount: f.chunkCount, received: [] })),
          })
        : undefined,
    );
    vi.mocked(runUploadInWorker).mockImplementationOnce(async (j) => {
      job = j;
      throw networkError();
    });
    renderSend();
    await addFile(new File(['x'], 'a.txt', { lastModified: 1 }));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    await userEvent.click(
      screen.getByRole('button', { name: /^(Resume upload|Encrypt & upload)$/ }),
    );
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    expect(calls.filter((c) => c.method === 'POST' && c.path === '/api/drops')).toHaveLength(1);
    expect(calls.some((c) => c.path === `/api/drops/${dropId}/upload-status`)).toBe(true);
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    expect(vi.mocked(runUploadInWorker).mock.calls.at(-1)![0].dropId).toBe(dropId);
  });

  it('after Dismiss, other files delete the failed drop before creating the new one (C-35)', async () => {
    const { calls } = mockApi();
    vi.mocked(runUploadInWorker).mockRejectedValueOnce(networkError());
    renderSend();
    await addFile(new File(['x'], 'a.txt', { lastModified: 1 }));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    const first = readResumeRecord()!;
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    await addFile(new File(['y'], 'b.txt', { lastModified: 2 }));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    const del = calls.findIndex(
      (c) =>
        c.method === 'DELETE' &&
        c.path === `/api/drops/${first.dropId}` &&
        c.headers.get('x-owner-token') === first.ownerToken,
    );
    const creates = calls.flatMap((c, i) =>
      c.method === 'POST' && c.path === '/api/drops' ? [i] : [],
    );
    expect(del).toBeGreaterThanOrEqual(0);
    expect(creates).toHaveLength(2);
    expect(del).toBeLessThan(creates[1]!);
  });

  it('a finished drop is neither resumed nor deleted by the next send of the same file (C-35)', async () => {
    const { calls } = mockApi();
    const file = new File(['x'], 'a.txt', { lastModified: 1 });
    renderSend();
    await addFile(file);
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Send another' }));
    await addFile(file);
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(
      await screen.findByRole('heading', { name: 'Your encrypted link is ready' }),
    ).toBeVisible();
    expect(calls.filter((c) => c.method === 'POST' && c.path === '/api/drops')).toHaveLength(2);
    expect(calls.some((c) => c.method === 'DELETE' || c.path.endsWith('/upload-status'))).toBe(
      false,
    );
  });

  it('a new drop over an unmatched record forgets the deleted drop when the create fails (C-35)', async () => {
    const oldDrop = generateFileId();
    writeResumeRecord({
      dropId: oldDrop,
      uploadToken: token(),
      dk: b64urlEncode(randomBytes(32)),
      files: [{ id: generateFileId(), size: 9, lastModified: 99, chunkCount: 1 }],
      ownerToken: token(),
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      createdAt: new Date().toISOString(),
      maxDownloads: 1,
      passwordProtected: false,
      anonymous: true,
    });
    const { calls } = mockApi((path, method) =>
      method === 'POST' && path === '/api/drops'
        ? json({ error: { code: 'INTERNAL', message: 'boom' } }, 500)
        : undefined,
    );
    renderSend();
    expect(await screen.findByText('An upload in this tab was interrupted')).toBeVisible();
    await addFile(new File(['something else entirely'], 'other.txt', { lastModified: 5 }));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE' && c.path === `/api/drops/${oldDrop}`)).toBe(
      true,
    );
    expect(readResumeRecord()).toBeNull();
    expect(screen.queryByText('An upload in this tab was interrupted')).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText('An upload in this tab was interrupted')).toBeNull();
  });

  it('Try again whose resume the server refuses asks to unlock instead of creating without the owner wrap (C-38)', async () => {
    const { calls } = mockApi((path, method) =>
      method === 'GET' && path.endsWith('/upload-status')
        ? json({ error: { code: 'EXPIRED', message: 'gone' } }, 410)
        : undefined,
    );
    useAuth.setState({ status: 'authenticated', user, accessToken: 'access' });
    useVault.getState().setAccountKey(await importAesKey(randomBytes(32)));
    vi.mocked(runUploadInWorker).mockRejectedValueOnce(networkError());
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    act(() => useVault.getState().lock('idle'));
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Your vault is locked')).toBeVisible();
    const creates = calls.filter((c) => c.method === 'POST' && c.path === '/api/drops');
    expect(creates).toHaveLength(1);
    expect(JSON.parse(creates[0]!.body!).ownerWrappedKey).toEqual(expect.any(String));
  });

  it('every view swap moves focus into the new view and announces it once (C-23)', async () => {
    mockApi();
    renderSend();
    const region = await screen.findByTestId('send-status');
    const header = () =>
      screen.getByRole('heading', { level: 1, name: 'Send files' }).closest('[tabindex="-1"]');
    const cancelButton = () => screen.getByRole('button', { name: 'Cancel' });
    const errorNotice = () =>
      screen.getByText('The upload did not finish').closest('[tabindex="-1"]');
    const resultHeading = () =>
      screen.getByRole('heading', { name: 'Your encrypted link is ready' });
    let upload: ReturnType<typeof controlledUpload>;
    const start = async (label: string) => {
      upload = controlledUpload();
      await userEvent.click(screen.getByRole('button', { name: label }));
    };
    await addFile(new File(['x'], 'a.txt'));

    const swaps: Array<{
      name: string;
      run: () => Promise<void>;
      focus: () => Element | null;
      status: RegExp;
    }> = [
      {
        name: 'compose -> running',
        run: () => start('Encrypt & upload'),
        focus: cancelButton,
        status: /^Upload started/,
      },
      {
        name: 'running -> compose (Cancel)',
        run: () => userEvent.click(cancelButton()),
        focus: header,
        status: /^Upload stopped/,
      },
      {
        name: 'compose -> running again',
        run: () => start('Encrypt & upload'),
        focus: cancelButton,
        status: /^Upload started/,
      },
      {
        name: 'running -> error',
        run: () => upload.fail(),
        focus: errorNotice,
        status: /^Upload failed/,
      },
      {
        name: 'error -> running (Try again)',
        run: () => start('Try again'),
        focus: cancelButton,
        status: /^Upload started/,
      },
      {
        name: 'running -> error again',
        run: () => upload.fail(),
        focus: errorNotice,
        status: /^Upload failed/,
      },
      {
        name: 'error -> compose (Dismiss)',
        run: () => userEvent.click(screen.getByRole('button', { name: 'Dismiss' })),
        focus: header,
        status: /^Error closed/,
      },
      {
        name: 'compose -> running (resume)',
        run: () => start('Resume upload'),
        focus: cancelButton,
        status: /^Upload started/,
      },
      {
        name: 'running -> done',
        run: () => upload.finish(),
        focus: resultHeading,
        status: /^Upload finished/,
      },
      {
        name: 'done -> compose (Send another)',
        run: () => userEvent.click(screen.getByRole('button', { name: 'Send another' })),
        focus: header,
        status: /^Ready for a new drop/,
      },
      {
        name: 'compose -> running -> done',
        run: async () => {
          await addFile(new File(['y'], 'b.txt'));
          await start('Encrypt & upload');
          await upload.finish();
        },
        focus: resultHeading,
        status: /^Upload finished/,
      },
      {
        name: 'done -> compose (Delete now)',
        run: async () => {
          await userEvent.click(screen.getByRole('button', { name: 'Delete now' }));
          const confirm = await screen.findByRole('dialog');
          await userEvent.click(within(confirm).getByRole('button', { name: /Delete/ }));
        },
        focus: header,
        status: /^Ready for a new drop/,
      },
    ];
    for (const swap of swaps) {
      await swap.run();
      await waitFor(() => expect(swap.focus(), swap.name).toHaveFocus());
      expect(region.textContent, swap.name).toMatch(swap.status);
      expect(screen.getByTestId('send-status'), swap.name).toBe(region);
    }
  });

  it('Try again with a locked vault focuses the unlock field and says why (C-23, C-38)', async () => {
    let creates = 0;
    mockApi((path, method) =>
      method === 'POST' && path === '/api/drops' && ++creates === 1
        ? json({ error: { code: 'INTERNAL', message: 'boom' } }, 500)
        : undefined,
    );
    useAuth.setState({ status: 'authenticated', user, accessToken: 'access' });
    useVault.getState().setAccountKey(await importAesKey(randomBytes(32)));
    renderSend();
    await addFile(new File(['x'], 'a.txt'));
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt & upload' }));
    expect(await screen.findByText('The upload did not finish')).toBeVisible();
    act(() => useVault.getState().lock('idle'));
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(screen.getByLabelText('Account password')).toHaveFocus());
    expect(screen.getByTestId('send-status')).toHaveTextContent('Unlock your vault to send again.');
  });
});
