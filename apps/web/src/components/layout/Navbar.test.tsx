/**
 * Navbar: Log in / Sign up for visitors, and no Sign up when the operator closed registration (ops-3).
 */
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, describe, expect, it } from 'vitest';
import { useAuth } from '../../stores/auth';
import { useServerConfig } from '../../stores/serverConfig';
import { Navbar } from './Navbar';

function renderNavbar() {
  const router = createMemoryRouter([{ path: '/', element: <Navbar /> }], {
    initialEntries: ['/'],
  });
  return render(<RouterProvider router={router} />);
}

/** Open the mobile menu, so the links of both the top bar and the menu are rendered. */
async function openMenu() {
  await userEvent.click(screen.getByRole('button', { name: 'Open menu' }));
  return document.getElementById('mobile-nav')!;
}

afterEach(() => {
  useAuth.setState(useAuth.getInitialState(), true);
  useServerConfig.setState(useServerConfig.getInitialState(), true);
});

describe('Navbar', () => {
  it('offers Log in and Sign up to visitors, in the bar and the mobile menu', async () => {
    useAuth.setState({ status: 'anonymous' });
    renderNavbar();
    const mobile = await openMenu();
    const signUp = screen.getAllByRole('link', { name: 'Sign up' });
    expect(signUp).toHaveLength(2);
    expect(within(mobile).getAllByRole('link', { name: 'Sign up' })).toHaveLength(1);
    for (const link of signUp) expect(link).toHaveAttribute('href', '/register');
  });

  it('hides Sign up when registration is closed, and keeps Log in', async () => {
    useAuth.setState({ status: 'anonymous' });
    useServerConfig.setState({ config: { anonymousUploads: true, registration: false } });
    renderNavbar();
    const mobile = await openMenu();
    expect(screen.queryAllByRole('link', { name: 'Sign up' })).toHaveLength(0);
    expect(screen.getAllByRole('link', { name: 'Log in' })).toHaveLength(2);
    expect(within(mobile).getAllByRole('link', { name: 'Log in' })).toHaveLength(1);
  });
});
