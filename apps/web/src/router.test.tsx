import type { Me } from '@cipherdrop/shared';
import { render, screen, waitFor } from '@testing-library/react';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, describe, expect, it } from 'vitest';
import { routes } from './router';
import { useAuth } from './stores/auth';
import { useVault } from './stores/vault';

const user: Me = {
  id: 'user_1',
  email: 'ada@example.com',
  role: 'ADMIN',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 100,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
};

async function renderRoute(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(<RouterProvider router={router} />);
  return router;
}

afterEach(() => {
  useAuth.setState(useAuth.getInitialState());
  useVault.setState(useVault.getInitialState());
});

describe('router: every lazy page renders inside the shell with its title', () => {
  const publicPages: Array<[path: string, title: string]> = [
    ['/', 'Send files'],
    ['/d/AAAAAAAAAAAAAAAAAAAAAA', 'Receive files'],
    ['/how-it-works', 'How it works'],
    ['/login', 'Log in'],
    ['/register', 'Create account'],
    ['/recover', 'Recover account'],
    ['/no/such/page', 'Page not found'],
  ];

  it.each(publicPages)('%s -> "%s"', async (path, title) => {
    useAuth.setState({ status: 'anonymous' });
    await renderRoute(path);
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument();
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe(`${title} · CipherDrop`));
  });

  const signedInPages: Array<[path: string, title: string]> = [
    ['/settings', 'Settings'],
    ['/unlock', 'Unlock vault'],
    ['/dashboard', 'Dashboard'],
    ['/admin', 'Admin'],
  ];

  it.each(signedInPages)('%s -> "%s" (signed in, vault unlocked)', async (path, title) => {
    useAuth.setState({
      status: 'authenticated',
      user,
      accessToken: 'token',
      accessTokenExpiresAt: Date.now() + 600_000,
    });
    useVault
      .getState()
      .setAccountKey(
        await crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']),
      );
    await renderRoute(path);
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument();
    expect(screen.getByRole('banner')).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe(`${title} · CipherDrop`));
  });

  it('shows Log in / Sign up to anonymous visitors and the account menu when signed in', async () => {
    useAuth.setState({ status: 'anonymous' });
    const { unmount } = render(
      <RouterProvider router={createMemoryRouter(routes, { initialEntries: ['/'] })} />,
    );
    await screen.findByRole('heading', { level: 1, name: 'Send files' });
    expect(screen.getAllByRole('link', { name: 'Log in' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Sign up' }).length).toBeGreaterThan(0);
    unmount();

    useAuth.setState({ status: 'authenticated', user, accessToken: 'token' });
    render(<RouterProvider router={createMemoryRouter(routes, { initialEntries: ['/'] })} />);
    await screen.findByRole('heading', { level: 1, name: 'Send files' });
    expect(
      screen.getByRole('button', { name: /ada@example.com account menu/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Unlock vault' })).toBeInTheDocument();
  });
});
