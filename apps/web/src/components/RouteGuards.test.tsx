import type { Me } from '@cipherdrop/shared';
import { render, screen } from '@testing-library/react';
import { createMemoryRouter, RouterProvider, useLocation } from 'react-router';
import { afterEach, describe, expect, it } from 'vitest';
import { useAuth } from '../stores/auth';
import { useVault } from '../stores/vault';
import { RequireAdmin, RequireAuth } from './RouteGuards';

const user: Me = {
  id: 'user_1',
  email: 'ada@example.com',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 100,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
};

function Where({ name }: { name: string }) {
  const location = useLocation();
  return (
    <p>
      {name} at {location.pathname}
      {location.search}
    </p>
  );
}

function renderAt(path: string) {
  const router = createMemoryRouter(
    [
      { path: '/', element: <Where name="home" /> },
      { path: '/login', element: <Where name="login" /> },
      { path: '/unlock', element: <Where name="unlock" /> },
      {
        element: <RequireAuth />,
        children: [{ path: '/settings', element: <Where name="settings" /> }],
      },
      {
        element: <RequireAuth needsVault />,
        children: [{ path: '/dashboard', element: <Where name="dashboard" /> }],
      },
      {
        element: <RequireAdmin />,
        children: [{ path: '/admin', element: <Where name="admin" /> }],
      },
    ],
    { initialEntries: [path] },
  );
  render(<RouterProvider router={router} />);
  return router;
}

function signIn(role: Me['role'] = 'USER') {
  useAuth.setState({
    status: 'authenticated',
    user: { ...user, role },
    accessToken: 'token',
    accessTokenExpiresAt: Date.now() + 600_000,
  });
}

async function accountKey() {
  return crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

afterEach(() => {
  useAuth.setState(useAuth.getInitialState());
  useVault.setState(useVault.getInitialState());
});

describe('RequireAuth', () => {
  it('waits for the boot refresh instead of redirecting', () => {
    renderAt('/settings');
    expect(screen.getByText('Restoring your session…')).toBeInTheDocument();
  });

  it('sends anonymous visitors to /login with next', async () => {
    useAuth.setState({ status: 'anonymous' });
    const router = renderAt('/settings?tab=sessions');
    expect(await screen.findByText(/^login at/)).toBeInTheDocument();
    expect(router.state.location.search).toBe('?next=%2Fsettings%3Ftab%3Dsessions');
  });

  it.each(['user', 'account-deleted'] as const)(
    'a deliberate %s logout lands on the home page, not on /login?next=',
    async (reason) => {
      useAuth.setState({ status: 'anonymous', logoutReason: reason });
      const router = renderAt('/settings?tab=account');
      expect(await screen.findByText(/^home at/)).toBeInTheDocument();
      expect(router.state.location.pathname).toBe('/');
      expect(router.state.location.search).toBe('');
    },
  );

  it('a session that expired elsewhere still goes to /login with next', async () => {
    useAuth.setState({ status: 'anonymous', logoutReason: 'session-expired' });
    const router = renderAt('/settings');
    await screen.findByText(/^login at/);
    expect(router.state.location.search).toBe('?next=%2Fsettings');
  });

  it('never copies the #fragment (keys) into ?next', async () => {
    useAuth.setState({ status: 'anonymous' });
    const router = renderAt('/settings#secret-key-material');
    await screen.findByText(/^login at/);
    expect(router.state.location.search).toBe('?next=%2Fsettings');
    expect(decodeURIComponent(router.state.location.search)).not.toContain('secret');
  });

  it('R7: a boot with no key on a vault route redirects to /unlock?next=', async () => {
    signIn();
    const router = renderAt('/dashboard');
    expect(await screen.findByText(/^unlock at/)).toBeInTheDocument();
    expect(router.state.location.search).toBe('?next=%2Fdashboard');
  });

  it('R7: an in-place lock never navigates (the page shows its locked state)', async () => {
    signIn();
    useVault.getState().setAccountKey(await accountKey());
    useVault.getState().lock('idle');
    renderAt('/dashboard');
    expect(screen.getByText('dashboard at /dashboard')).toBeInTheDocument();
  });

  it('routes that do not need the vault render while it is locked', () => {
    signIn();
    renderAt('/settings');
    expect(screen.getByText('settings at /settings')).toBeInTheDocument();
  });
});

describe('RequireAdmin', () => {
  it('shows a 403 state to non-admins', () => {
    signIn('USER');
    renderAt('/admin');
    expect(screen.getByRole('heading', { name: 'Admins only' })).toBeInTheDocument();
    expect(screen.queryByText(/^admin at/)).not.toBeInTheDocument();
  });

  it('renders the admin route for admins', () => {
    signIn('ADMIN');
    renderAt('/admin');
    expect(screen.getByText('admin at /admin')).toBeInTheDocument();
  });

  it('redirects anonymous visitors to /login', async () => {
    useAuth.setState({ status: 'anonymous' });
    const router = renderAt('/admin');
    await screen.findByText(/^login at/);
    expect(router.state.location.search).toBe('?next=%2Fadmin');
  });
});
