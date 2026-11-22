import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  apiError,
  authSuccess,
  installInProcessKdfWorker,
  mockApi,
  renderRoutes,
  resetStores,
} from '../account/testkit';
import { useAuth } from '../../stores/auth';
import { useServerConfig } from '../../stores/serverConfig';
import { useVault } from '../../stores/vault';
import { Component as RegisterPage } from './RegisterPage';

const routes = [
  { path: '/register', Component: RegisterPage },
  { path: '/login', element: <p>login page</p> },
  { path: '/dashboard', element: <p>dashboard page</p> },
];

const PASSWORD = 'correct horse battery staple';

async function fillAndSubmit(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Email'), 'ada@example.com');
  await user.type(screen.getByLabelText('Password'), PASSWORD);
  await user.type(screen.getByLabelText('Confirm password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Create account' }));
}

beforeEach(() => {
  resetStores();
  installInProcessKdfWorker();
});
afterEach(() => resetStores());

describe('RegisterPage', () => {
  it('continue disabled until recovery key saved', async () => {
    const api = mockApi({ 'POST /api/auth/register': { status: 201, json: authSuccess() } });
    const user = userEvent.setup();
    renderRoutes(routes, '/register');
    await fillAndSubmit(user);

    expect(
      await screen.findByText('Save your recovery key', {}, { timeout: 15_000 }),
    ).toBeVisible();
    const cont = screen.getByRole('button', { name: /continue to my files/i });
    expect(cont).toBeDisabled();

    await user.click(screen.getByLabelText('I saved my recovery key'));
    expect(cont).toBeEnabled();
    await user.click(cont);
    expect(await screen.findByText('dashboard page')).toBeVisible();

    // The request carries derived keys only: never the password, and the vault opened with a locked-down key.
    const body = JSON.stringify(api.calls[0]?.body);
    expect(body).not.toContain(PASSWORD);
    expect(api.calls[0]?.body).toMatchObject({ email: 'ada@example.com' });
    expect(useAuth.getState().status).toBe('authenticated');
    expect(useVault.getState().accountKey?.extractable).toBe(false);
  }, 30_000);

  it('shows the recovery key in 2 rows of 4 groups', async () => {
    mockApi({ 'POST /api/auth/register': { status: 201, json: authSuccess() } });
    const user = userEvent.setup();
    renderRoutes(routes, '/register');
    await fillAndSubmit(user);
    await screen.findByText('Save your recovery key', {}, { timeout: 15_000 });
    const rows = screen.getAllByTestId('recovery-key-row').map((r) => r.textContent);
    expect(rows).toHaveLength(2);
    expect(rows.join('-')).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
  }, 30_000);

  it('validates before deriving anything', async () => {
    const api = mockApi({});
    const user = userEvent.setup();
    renderRoutes(routes, '/register');
    await user.type(screen.getByLabelText('Email'), 'not-an-email');
    await user.type(screen.getByLabelText('Password'), 'short');
    await user.type(screen.getByLabelText('Confirm password'), 'different');
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByText('Enter a valid email address.')).toBeVisible();
    expect(screen.getByText('Use at least 10 characters.')).toBeVisible();
    expect(screen.getByText('The two passwords do not match.')).toBeVisible();
    expect(api.fetchMock).not.toHaveBeenCalled();
  });

  it('reports an existing email without leaving the form', async () => {
    mockApi({ 'POST /api/auth/register': apiError(409, 'CONFLICT', 'Already exists') });
    const user = userEvent.setup();
    renderRoutes(routes, '/register');
    await fillAndSubmit(user);
    await waitFor(
      () =>
        expect(screen.getByRole('alert')).toHaveTextContent(
          /account with this email already exists/i,
        ),
      { timeout: 15_000 },
    );
    expect(screen.queryByText('Save your recovery key')).toBeNull();
    expect(useAuth.getState().status).not.toBe('authenticated');
    vi.restoreAllMocks();
  }, 30_000);

  it('registration switched off: says so, offers log in and shows no form (ops-3)', async () => {
    const api = mockApi({});
    useServerConfig.setState({ config: { anonymousUploads: true, registration: false } });
    const user = userEvent.setup();
    renderRoutes(routes, '/register');
    expect(await screen.findByText('This server is not accepting new accounts')).toBeVisible();
    expect(screen.queryByLabelText('Email')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Create account' })).toBeNull();
    await user.click(screen.getByRole('link', { name: 'Log in' }));
    expect(await screen.findByText('login page')).toBeVisible();
    expect(api.fetchMock).not.toHaveBeenCalled();
  });

  it('a 403 FEATURE_DISABLED on submit replaces the form with the same notice (ops-3)', async () => {
    mockApi({
      'POST /api/auth/register': {
        status: 403,
        json: {
          error: { code: 'FEATURE_DISABLED', message: 'off', details: { feature: 'registration' } },
        },
      },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/register');
    await fillAndSubmit(user);
    expect(
      await screen.findByText('This server is not accepting new accounts', {}, { timeout: 15_000 }),
    ).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Create account' })).toBeNull();
    expect(useAuth.getState().status).not.toBe('authenticated');
  }, 30_000);
});
