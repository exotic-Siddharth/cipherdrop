import {
  AAD,
  b64urlEncode,
  encryptManifest,
  generateDropKey,
  generateFileId,
  importAesKey,
  randomBytes,
  wrapKey,
} from '@cipherdrop/crypto';
import { CHUNK_SIZE } from '@cipherdrop/crypto/constants';
import type { Me, OwnerDropSummary } from '@cipherdrop/shared';
import { QueryClientProvider } from '@tanstack/react-query';
import { act, configure, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { queryClient } from '../../lib/queryClient';
import { routes } from '../../router';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';

// The machine running these tests is shared and busy: give async work room.
configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

const me: Me = {
  id: 'ckuser000000000000000001',
  email: 'ada@example.com',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 1024 ** 3,
  storageUsedBytes: 300 * 1024 ** 2,
  createdAt: new Date('2026-10-01T00:00:00Z').toISOString(),
};

interface Fixture {
  summary: OwnerDropSummary;
  dk: Uint8Array;
}

async function makeDrop(
  accountKey: CryptoKey,
  names: string[],
  extra: Partial<OwnerDropSummary> & { note?: string | null; noOwnerKey?: boolean } = {},
): Promise<Fixture> {
  const dk = generateDropKey();
  const { note = null, noOwnerKey = false, ...rest } = extra;
  const encryptedManifest = await encryptManifest(dk, {
    v: 1,
    createdAt: Date.now(),
    note,
    files: names.map((name) => ({
      id: generateFileId(),
      name,
      size: 1234,
      type: 'text/plain',
      lastModified: 1,
      chunkSize: CHUNK_SIZE,
      chunkCount: 1,
    })),
  });
  const summary: OwnerDropSummary = {
    id: generateFileId(),
    status: 'READY',
    fileCount: names.length,
    totalBytes: 2048,
    maxDownloads: 3,
    downloadCount: 1,
    downloadsRemaining: 2,
    expiresAt: new Date(Date.now() + 3 * 86_400_000).toISOString(),
    createdAt: new Date(Date.now() - 3_600_000).toISOString(),
    lastOpenedAt: null,
    passwordProtected: false,
    encryptedManifest,
    ownerWrappedKey: noOwnerKey ? null : await wrapKey(accountKey, dk, AAD.WRAP_OWNER),
    ...rest,
  };
  return { summary, dk };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Serve GET /me/drops from `lists[status]`, DELETE /drops/:id and GET /me. */
function mockApi(lists: Partial<Record<'active' | 'expired' | 'all', OwnerDropSummary[]>>) {
  const calls: Array<{ method: string; path: string; search: string }> = [];
  const state = { ...lists };
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), 'http://localhost');
    const method = init.method ?? 'GET';
    calls.push({ method, path: url.pathname, search: url.search });
    if (method === 'GET' && url.pathname === '/api/me/drops') {
      const status = (url.searchParams.get('status') ?? 'active') as 'active' | 'expired' | 'all';
      const items = state[status] ?? [];
      return json({ items, total: items.length, page: 1, pageSize: 10 });
    }
    if (method === 'GET' && url.pathname === '/api/me') return json({ user: me });
    if (method === 'DELETE' && url.pathname.startsWith('/api/drops/')) {
      const id = decodeURIComponent(url.pathname.split('/').pop() ?? '');
      state.active = (state.active ?? []).filter((d) => d.id !== id);
      return new Response(null, { status: 204 });
    }
    return json({ error: { code: 'NOT_FOUND', message: 'no' } }, 404);
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

function renderDashboard() {
  const router = createMemoryRouter(routes, { initialEntries: ['/dashboard'] });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

let accountKey: CryptoKey;

beforeAll(async () => {
  await import('./DashboardPage');
}, 60_000);

beforeEach(async () => {
  accountKey = await importAesKey(randomBytes(32));
  useAuth.setState({ status: 'authenticated', user: me, accessToken: 'test-token' });
  useVault.getState().setAccountKey(accountKey);
});

afterEach(() => {
  vi.unstubAllGlobals();
  queryClient.clear();
  useAuth.setState(useAuth.getInitialState());
  useVault.setState(useVault.getInitialState());
});

describe('DashboardPage', () => {
  it('renders decrypted file names, status, downloads, expiry and the storage meter', async () => {
    const a = await makeDrop(accountKey, ['quarterly-report.pdf', 'appendix.csv'], {
      note: 'for the audit',
    });
    const b = await makeDrop(accountKey, ['holiday.png'], { downloadCount: 0, maxDownloads: 1 });
    mockApi({ active: [a.summary, b.summary] });
    renderDashboard();

    expect(await screen.findByText('quarterly-report.pdf')).toBeVisible();
    expect(screen.getByText('+1 more')).toBeVisible();
    expect(screen.getByText('for the audit')).toBeVisible();
    expect(screen.getByText('holiday.png')).toBeVisible();
    expect(screen.getByText('1/3')).toBeVisible();
    expect(screen.getByText('0/1')).toBeVisible();
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Expires in/).length).toBeGreaterThan(0);
    const meter = screen.getByRole('meter', { name: 'Storage used' });
    expect(meter).toHaveAttribute('aria-valuetext', '300 MB of 1 GB used');
  });

  it('lock() while mounted shows locked rows', async () => {
    const a = await makeDrop(accountKey, ['secret-plans.docx']);
    const router = mockApiAndRender([a.summary]);
    expect(await screen.findByText('secret-plans.docx')).toBeVisible();

    act(() => {
      useVault.getState().lock('idle');
    });

    await waitFor(() => expect(screen.queryByText('secret-plans.docx')).toBeNull());
    expect(screen.getAllByText('Locked').length).toBeGreaterThan(0);
    const unlock = screen.getByRole('link', { name: 'Unlock' });
    expect(unlock).toHaveAttribute('href', '/unlock?next=%2Fdashboard');
    // R7: locking in place never navigates.
    expect(router.state.location.pathname).toBe('/dashboard');
    // The non-password link cannot be rebuilt while locked.
    expect(screen.getByRole('button', { name: /Copy link/ })).toBeDisabled();

    // Unlocking again brings the names back without a reload.
    act(() => {
      useVault.getState().setAccountKey(accountKey);
    });
    expect(await screen.findByText('secret-plans.docx')).toBeVisible();
  });

  it('Copy link rebuilds /d/id#key from the owner wrap', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const a = await makeDrop(accountKey, ['notes.txt']);
    mockApi({ active: [a.summary] });
    renderDashboard();
    await screen.findByText('notes.txt');

    await userEvent.click(screen.getByRole('button', { name: /Copy link/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText).toHaveBeenCalledWith(
      `${window.location.origin}/d/${a.summary.id}#${b64urlEncode(a.dk)}`,
    );
  });

  it('Copy link for a password drop copies the keyless link, even while locked', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const a = await makeDrop(accountKey, ['payroll.xlsx'], { passwordProtected: true });
    mockApi({ active: [a.summary] });
    renderDashboard();
    await screen.findByText('payroll.xlsx');
    act(() => {
      useVault.getState().lock('manual');
    });
    await screen.findByRole('link', { name: 'Unlock' });

    await userEvent.click(screen.getByRole('button', { name: /Copy link/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/d/${a.summary.id}`);
  });

  it('a drop created without an owner wrap shows "Name unavailable" and cannot rebuild its link', async () => {
    const a = await makeDrop(accountKey, ['x.bin'], { noOwnerKey: true });
    mockApi({ active: [a.summary] });
    renderDashboard();
    expect(await screen.findByText('Name unavailable')).toBeVisible();
    expect(screen.getByRole('button', { name: /Copy link/ })).toBeDisabled();
  });

  it('a manifest that fails to decrypt shows an error row, not a crash', async () => {
    const other = await importAesKey(randomBytes(32));
    const a = await makeDrop(other, ['foreign.bin']); // wrapped under a different account key
    mockApi({ active: [a.summary] });
    renderDashboard();
    expect(await screen.findByText("Couldn't decrypt names")).toBeVisible();
  });

  it('deleting asks for confirmation, then removes the drop and refreshes the meter', async () => {
    const a = await makeDrop(accountKey, ['old.zip']);
    const calls = mockApi({ active: [a.summary] });
    renderDashboard();
    await screen.findByText('old.zip');

    await userEvent.click(screen.getByRole('button', { name: /Delete drop/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete this drop?' });
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete drop' }));

    await waitFor(() =>
      expect(calls).toContainEqual(
        expect.objectContaining({ method: 'DELETE', path: `/api/drops/${a.summary.id}` }),
      ),
    );
    expect(await screen.findByText('No active drops')).toBeVisible();
    expect(screen.getByRole('link', { name: 'Send a drop' })).toHaveAttribute('href', '/');
  });

  it('filter tabs request the matching status and reset to the first page', async () => {
    const a = await makeDrop(accountKey, ['live.txt']);
    const b = await makeDrop(accountKey, ['gone.txt'], {
      status: 'EXPIRED',
      expiresAt: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    });
    const calls = mockApi({
      active: [a.summary],
      expired: [b.summary],
      all: [a.summary, b.summary],
    });
    renderDashboard();
    await screen.findByText('live.txt');

    await userEvent.click(screen.getByRole('tab', { name: 'Expired' }));
    expect(await screen.findByText('gone.txt')).toBeVisible();
    expect(screen.queryByText('live.txt')).toBeNull();
    expect(within(screen.getByRole('list', { name: 'Drops' })).getByText('Expired')).toBeVisible();
    expect(screen.getByText(/Expired 2 h ago/)).toBeVisible();
    expect(calls.some((c) => c.search.includes('status=expired'))).toBe(true);
    // Expired drops cannot be shared any more.
    expect(screen.getByRole('button', { name: /Copy link/ })).toBeDisabled();

    await userEvent.click(screen.getByRole('tab', { name: 'All' }));
    expect(await screen.findByText('live.txt')).toBeVisible();
    expect(screen.getByText('gone.txt')).toBeVisible();
  });

  it('shows an error state with retry when the list fails to load', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ error: { code: 'NOT_FOUND', message: 'nope' } }, 404)),
    );
    renderDashboard();
    expect(await screen.findByText("Couldn't load your drops")).toBeVisible();
    expect(screen.getByRole('button', { name: /retry|try again/i })).toBeVisible();
  });
});

function mockApiAndRender(items: OwnerDropSummary[]) {
  mockApi({ active: items });
  return renderDashboard();
}
