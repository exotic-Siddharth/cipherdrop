import type {
  AdminReport,
  AdminReportPage,
  AdminStats,
  AdminUser,
  AdminUserPage,
  Me,
} from '@cipherdrop/shared';
import { QueryClientProvider } from '@tanstack/react-query';
import { configure, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { queryClient } from '../../lib/queryClient';
import { routes } from '../../router';
import { useAuth } from '../../stores/auth';

// The machine running these tests is shared and busy: give async work room.
configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

const GIB = 1024 ** 3;
const KEY = 'A'.repeat(43);
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

const admin: Me = {
  id: 'ckadmin00000000000000001',
  email: 'root@example.com',
  role: 'ADMIN',
  totpEnabled: true,
  autoLockMinutes: 15,
  storageQuotaBytes: 5 * GIB,
  storageUsedBytes: 0,
  createdAt: iso(-30 * 86_400_000),
};

function stats(): AdminStats {
  const days = Array.from({ length: 14 }, (_, i) => {
    const d = new Date(Date.UTC(2026, 10, 8 - (13 - i)));
    return {
      date: d.toISOString().slice(0, 10),
      drops: i === 12 ? 9 : i % 4,
      bytes: i === 12 ? 300 * 1024 ** 2 : (i % 4) * 1024 ** 2,
    };
  });
  return {
    users: 42,
    activeDrops: 17,
    totalDrops: 1284,
    storageBytes: 3 * GIB,
    openReports: 2,
    uploadsLast14d: days,
  };
}

/** A canonical 22-char drop id (b64url of 16 bytes: the last char is one of A, Q, g, w). */
const dropId = (n: number) => `${String.fromCharCode(96 + n).repeat(21)}A`;

function reports(): AdminReport[] {
  const base = {
    details: null,
    createdAt: iso(-3_600_000),
    drop: {
      status: 'READY' as const,
      fileCount: 2,
      totalBytes: 4096,
      ownerEmail: 'owner@example.com',
      createdAt: iso(-86_400_000),
    },
  };
  return [
    {
      ...base,
      id: 'ckreport0000000000000001',
      reason: 'MALWARE',
      status: 'OPEN',
      hasKey: true,
      decryptionKey: KEY,
      details: 'Contains a trojan <b>dropper</b>',
      drop: { ...base.drop, id: dropId(1) },
    },
    {
      ...base,
      id: 'ckreport0000000000000002',
      reason: 'PHISHING',
      status: 'OPEN',
      hasKey: false,
      decryptionKey: null,
      drop: { ...base.drop, id: dropId(2), ownerEmail: null },
    },
  ];
}

function users(): AdminUser[] {
  const base = {
    totpEnabled: false,
    dropCount: 3,
    lockedUntil: null,
    createdAt: iso(-10 * 86_400_000),
    storageQuotaBytes: 5 * GIB,
    storageUsedBytes: 2 * GIB,
  };
  return [
    { ...base, id: admin.id, email: admin.email, role: 'ADMIN', totpEnabled: true },
    { ...base, id: 'ckuser000000000000000002', email: 'bob@example.com', role: 'USER' },
  ];
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Call {
  method: string;
  path: string;
  search: URLSearchParams;
  body?: unknown;
}

function mockApi(overrides: { reportItems?: AdminReport[] } = {}) {
  const calls: Call[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), 'http://localhost');
    const method = init.method ?? 'GET';
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: url.pathname, search: url.searchParams, body });
    if (method === 'GET' && url.pathname === '/api/admin/stats') return json(stats());
    if (method === 'GET' && url.pathname === '/api/admin/reports') {
      const items = overrides.reportItems ?? reports();
      const page: AdminReportPage = { items, total: items.length, page: 1, pageSize: 10 };
      return json(page);
    }
    if (method === 'GET' && url.pathname === '/api/admin/users') {
      const search = url.searchParams.get('search')?.toLowerCase();
      const items = users().filter((u) => !search || u.email.includes(search));
      const page: AdminUserPage = { items, total: items.length, page: 1, pageSize: 10 };
      return json(page);
    }
    if (method === 'POST' && url.pathname.startsWith('/api/admin/reports/')) {
      return new Response(null, { status: 204 });
    }
    if (method === 'PATCH' && url.pathname.startsWith('/api/admin/users/')) {
      const id = decodeURIComponent(url.pathname.split('/').pop() ?? '');
      const user = users().find((u) => u.id === id)!;
      return json({ user: { ...user, ...(body as object) } });
    }
    return json({ error: { code: 'NOT_FOUND', message: 'no' } }, 404);
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

function renderAdmin() {
  const router = createMemoryRouter(routes, { initialEntries: ['/admin'] });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

beforeAll(async () => {
  await import('./AdminPage');
}, 60_000);

beforeEach(() => {
  useAuth.setState({ status: 'authenticated', user: admin, accessToken: 'test-token' });
});

afterEach(() => {
  vi.unstubAllGlobals();
  queryClient.clear();
  useAuth.setState(useAuth.getInitialState());
});

describe('AdminPage stats and chart', () => {
  it('shows the stat cards and an accessible uploads chart that can switch measure and show a table', async () => {
    mockApi();
    renderAdmin();

    const statList = await screen.findByRole('list', { name: 'Statistics' });
    expect(within(statList).getByText('1,284')).toBeVisible();
    expect(within(statList).getByText('3 GB')).toBeVisible();
    expect(within(statList).getByText('Needs review')).toBeVisible();

    const group = await screen.findByRole('group', { name: 'Uploads per day, drops' });
    const columns = within(group).getAllByRole('button');
    expect(columns).toHaveLength(14);
    expect(columns[12]).toHaveAccessibleName(/9 drops, 300 MB/);

    await userEvent.click(screen.getByRole('tab', { name: 'Bytes' }));
    expect(screen.getByRole('group', { name: 'Uploads per day, bytes' })).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: 'Table view' }));
    const table = screen.getByRole('table', { name: 'Uploads per day, last 14 days (UTC)' });
    expect(within(table).getAllByRole('row')).toHaveLength(15);
    expect(screen.getByRole('button', { name: 'Chart view' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });

  it('moves between chart columns with the arrow keys', async () => {
    mockApi();
    renderAdmin();
    const group = await screen.findByRole('group', { name: 'Uploads per day, drops' });
    const columns = within(group).getAllByRole('button');
    columns[13]!.focus();
    await userEvent.keyboard('{ArrowLeft}');
    expect(columns[12]).toHaveFocus();
    await userEvent.keyboard('{Home}');
    expect(columns[0]).toHaveFocus();
  });
});

describe('AdminPage reports', () => {
  it('Review opens /d/:id?review=1#<key> only when the report has a key', async () => {
    mockApi();
    renderAdmin();
    const review = await screen.findByRole('link', { name: `Review drop ${dropId(1)}` });
    expect(review).toHaveAttribute('href', `/d/${dropId(1)}?review=1#${KEY}`);
    expect(
      screen.getByRole('button', { name: /Review drop .* \(no key supplied\)/ }),
    ).toBeDisabled();
    // Reporter text is rendered as text, never as markup.
    expect(screen.getByText('Contains a trojan <b>dropper</b>')).toBeVisible();
  });

  it('Disable asks for confirmation, then resolves with DISABLE_DROP', async () => {
    const calls = mockApi();
    renderAdmin();
    await userEvent.click(await screen.findByRole('button', { name: `Disable drop ${dropId(1)}` }));
    const dialog = await screen.findByRole('dialog', { name: 'Disable this drop?' });
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disable drop' }));
    await waitFor(() =>
      expect(calls).toContainEqual(
        expect.objectContaining({
          method: 'POST',
          path: '/api/admin/reports/ckreport0000000000000001/resolve',
          body: { action: 'DISABLE_DROP' },
        }),
      ),
    );
  });

  it('Dismiss confirms, and cancelling sends nothing', async () => {
    const calls = mockApi();
    renderAdmin();
    await userEvent.click(
      await screen.findByRole('button', { name: 'Dismiss report ckreport0000000000000002' }),
    );
    let dialog = await screen.findByRole('dialog', { name: 'Dismiss this report?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await userEvent.click(
      screen.getByRole('button', { name: 'Dismiss report ckreport0000000000000002' }),
    );
    dialog = await screen.findByRole('dialog', { name: 'Dismiss this report?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Dismiss report' }));
    await waitFor(() =>
      expect(calls).toContainEqual(
        expect.objectContaining({
          method: 'POST',
          path: '/api/admin/reports/ckreport0000000000000002/resolve',
          body: { action: 'DISMISS' },
        }),
      ),
    );
  });

  it('filters by status and shows the empty state', async () => {
    const calls = mockApi({ reportItems: [] });
    renderAdmin();
    expect(await screen.findByText('No open reports')).toBeVisible();
    expect(calls.find((c) => c.path === '/api/admin/reports')?.search.get('status')).toBe('OPEN');
    await userEvent.click(screen.getByRole('tab', { name: 'All' }));
    await waitFor(() =>
      expect(
        calls.filter((c) => c.path === '/api/admin/reports').some((c) => !c.search.has('status')),
      ).toBe(true),
    );
  });
});

describe('AdminPage users', () => {
  async function openEdit(email: string) {
    await userEvent.click(await screen.findByRole('button', { name: `Edit ${email}` }));
    return screen.findByRole('dialog', { name: 'Edit user' });
  }

  it('searches by email (debounced)', async () => {
    const calls = mockApi();
    renderAdmin();
    await screen.findByText('bob@example.com');
    const usersTable = () => screen.getByRole('list', { name: 'Users' });
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search users' }), 'bob');
    await waitFor(() =>
      expect(
        calls.some((c) => c.path === '/api/admin/users' && c.search.get('search') === 'bob'),
      ).toBe(true),
    );
    await waitFor(() => expect(within(usersTable()).queryByText('root@example.com')).toBeNull());
    expect(within(usersTable()).getByText('bob@example.com')).toBeVisible();
  });

  it.each([
    ['', 'Enter a quota in GB.'],
    ['abc', /plain number/],
    ['-5', /plain number/],
    ['1e3', /plain number/],
    ['2.555', /plain number/],
    ['0', /greater than 0/],
    ['20000', /cannot exceed 10,240 GB/],
  ])('quota %j is rejected without calling the API', async (value, message) => {
    const calls = mockApi();
    renderAdmin();
    const dialog = await openEdit('bob@example.com');
    const input = within(dialog).getByLabelText('Storage quota');
    await userEvent.clear(input);
    if (value) await userEvent.type(input, value);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    expect(await within(dialog).findByText(message)).toBeVisible();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
  });

  it('saves a valid quota in bytes and a role change', async () => {
    const calls = mockApi();
    renderAdmin();
    const dialog = await openEdit('bob@example.com');
    const input = within(dialog).getByLabelText('Storage quota');
    await userEvent.clear(input);
    await userEvent.type(input, '2.5');
    await userEvent.selectOptions(within(dialog).getByLabelText('Role'), 'ADMIN');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    await waitFor(() =>
      expect(calls).toContainEqual(
        expect.objectContaining({
          method: 'PATCH',
          path: '/api/admin/users/ckuser000000000000000002',
          body: { role: 'ADMIN', storageQuotaBytes: 2.5 * GIB },
        }),
      ),
    );
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('sends only what changed, warns below usage, and locks your own role', async () => {
    const calls = mockApi();
    renderAdmin();
    let dialog = await openEdit('bob@example.com');
    const save = within(dialog).getByRole('button', { name: 'Save changes' });
    expect(save).toBeDisabled();
    const input = within(dialog).getByLabelText('Storage quota');
    await userEvent.clear(input);
    await userEvent.type(input, '1');
    expect(within(dialog).getByText(/below the current usage/)).toBeVisible();
    await userEvent.click(save);
    await waitFor(() =>
      expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ storageQuotaBytes: GIB }),
    );
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    dialog = await openEdit('root@example.com');
    expect(within(dialog).getByLabelText('Role')).toBeDisabled();
    expect(within(dialog).getByText('You cannot change your own role.')).toBeVisible();
  });
});
