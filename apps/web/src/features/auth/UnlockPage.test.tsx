import { createAccountBundle, KDF_MIN } from '@cipherdrop/crypto';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { queryClient, queryKeys } from '../../lib/queryClient';
import { useVault } from '../../stores/vault';
import {
  installInProcessKdfWorker,
  mockApi,
  renderRoutes,
  resetStores,
  signIn,
} from '../account/testkit';
import { Component as UnlockPage } from './UnlockPage';

const PASSWORD = 'correct horse battery staple';
let vault: { wrappedAccountKey: string; kdf: typeof KDF_MIN & { salt: string } };

beforeAll(async () => {
  const bundle = await createAccountBundle(PASSWORD, KDF_MIN);
  vault = { wrappedAccountKey: bundle.wrappedAccountKey, kdf: bundle.kdf };
});

const routes = [
  { path: '/unlock', Component: UnlockPage },
  { path: '/dashboard', element: <p>dashboard page</p> },
  { path: '/', element: <p>home page</p> },
];

beforeEach(() => {
  resetStores();
  installInProcessKdfWorker();
  signIn();
  // The vault payload was already loaded (as the page does on mount): unlocking itself is purely local.
  queryClient.setQueryData(queryKeys.vault(), vault);
});
afterEach(() => resetStores());

describe('UnlockPage', () => {
  it('wrong password shows error without network call', async () => {
    const api = mockApi({});
    const user = userEvent.setup();
    renderRoutes(routes, '/unlock?next=%2Fdashboard');
    await user.type(await screen.findByLabelText('Password'), 'definitely the wrong one');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Wrong password. Your vault stays locked.',
    );
    expect(api.fetchMock).not.toHaveBeenCalled();
    expect(useVault.getState().accountKey).toBeNull();
    expect(screen.queryByText('dashboard page')).toBeNull();
  });

  it('the right password unlocks locally and continues to ?next', async () => {
    const api = mockApi({});
    const user = userEvent.setup();
    renderRoutes(routes, '/unlock?next=%2Fdashboard');
    await user.type(await screen.findByLabelText('Password'), PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    expect(await screen.findByText('dashboard page')).toBeVisible();
    expect(useVault.getState().accountKey?.extractable).toBe(false);
    expect(api.fetchMock).not.toHaveBeenCalled();
  });

  it('loads the vault from the server when it is not cached yet', async () => {
    queryClient.clear();
    const api = mockApi({ 'GET /api/auth/vault': { json: vault } });
    const user = userEvent.setup();
    renderRoutes(routes, '/unlock');
    await user.type(await screen.findByLabelText('Password'), PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(await screen.findByText('dashboard page')).toBeVisible();
    expect(api.calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /api/auth/vault']);
  });

  it('shows the signed-in email and a Sign out button', async () => {
    mockApi({ 'POST /api/auth/logout': { status: 204 } });
    const user = userEvent.setup();
    renderRoutes(routes, '/unlock');
    expect(await screen.findByText('ada@example.com')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('home page')).toBeVisible();
  });
});
