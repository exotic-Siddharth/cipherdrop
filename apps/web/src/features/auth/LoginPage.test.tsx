import { createAccountBundle, KDF_MIN, b64urlEncode } from '@cipherdrop/crypto';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  apiError,
  authSuccess,
  installInProcessKdfWorker,
  mockApi,
  renderRoutes,
  resetStores,
} from '../account/testkit';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';
import { Component as LoginPage } from './LoginPage';

const PASSWORD = 'correct horse battery staple';
let bundle: Awaited<ReturnType<typeof createAccountBundle>>;

beforeAll(async () => {
  bundle = await createAccountBundle(PASSWORD, KDF_MIN);
});

const routes = [
  { path: '/login', Component: LoginPage },
  { path: '/register', element: <p>register page</p> },
  { path: '/recover', element: <p>recover page</p> },
  { path: '/dashboard', element: <p>dashboard page</p> },
  { path: '/send', element: <p>send page</p> },
];

const baseHandlers = () => ({
  'POST /api/auth/prelogin': { json: { kdf: bundle.kdf } },
  'GET /api/auth/vault': {
    json: { wrappedAccountKey: bundle.wrappedAccountKey, kdf: bundle.kdf },
  },
});

async function submitCredentials(user: ReturnType<typeof userEvent.setup>, password = PASSWORD) {
  await user.type(screen.getByLabelText('Email'), 'ada@example.com');
  await user.type(screen.getByLabelText('Password'), password);
  await user.click(screen.getByRole('button', { name: 'Log in' }));
}

beforeEach(() => {
  resetStores();
  installInProcessKdfWorker();
});
afterEach(() => resetStores());

describe('LoginPage', () => {
  it('mfaRequired switches to code step', async () => {
    mockApi({
      ...baseHandlers(),
      'POST /api/auth/login': { json: { mfaRequired: true, mfaToken: 'mfa-token-1' } },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/login');
    await submitCredentials(user);

    expect(await screen.findByRole('heading', { name: 'Two-step verification' })).toBeVisible();
    expect(screen.getByLabelText('6-digit code')).toBeVisible();
    expect(screen.queryByLabelText('Password')).toBeNull();

    await user.click(screen.getByRole('button', { name: 'Use a backup code instead' }));
    expect(screen.getByLabelText('Backup code')).toBeVisible();
  });

  it('finishes the TOTP step, unlocks the vault and goes to ?next', async () => {
    const api = mockApi({
      ...baseHandlers(),
      'POST /api/auth/login': { json: { mfaRequired: true, mfaToken: 'mfa-token-1' } },
      'POST /api/auth/login/mfa': { json: authSuccess({ totpEnabled: true }) },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/login?next=%2Fsend');
    await submitCredentials(user);
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify and log in' }));

    expect(await screen.findByText('send page')).toBeVisible();
    expect(useAuth.getState().status).toBe('authenticated');
    expect(useVault.getState().accountKey?.extractable).toBe(false);
    const login = api.calls.find((c) => c.path === '/api/auth/login');
    expect(login?.body).toEqual({
      email: 'ada@example.com',
      authKey: b64urlEncode(bundle.authKey),
    });
    expect(api.calls.find((c) => c.path === '/api/auth/login/mfa')?.body).toEqual({
      mfaToken: 'mfa-token-1',
      code: '123456',
    });
    // Credentials are never sent with the session token.
    expect(login?.headers.get('authorization')).toBeNull();
  });

  it('shows one generic message for a failed sign-in', async () => {
    mockApi({
      ...baseHandlers(),
      'POST /api/auth/login': apiError(401, 'UNAUTHORIZED', 'Invalid credentials'),
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/login');
    await submitCredentials(user, 'wrong password entirely');
    expect(await screen.findByRole('alert')).toHaveTextContent(/incorrect email or password/i);
    expect(useAuth.getState().status).not.toBe('authenticated');
  });

  it('tells the user how long to wait when rate limited', async () => {
    mockApi({
      ...baseHandlers(),
      'POST /api/auth/login': {
        status: 429,
        json: { error: { code: 'RATE_LIMITED', message: 'Too many requests' } },
        headers: { 'retry-after': '120' },
      },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/login');
    await submitCredentials(user);
    expect(await screen.findByRole('alert')).toHaveTextContent(/try again in 2 min/i);
  });

  it('refuses unsafe KDF params from the server without sending a login', async () => {
    const api = mockApi({
      'POST /api/auth/prelogin': { json: { kdf: { ...bundle.kdf, memoryKiB: 8 } } },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/login');
    await submitCredentials(user);
    // The shared schema already bounds the params, so the response is rejected as invalid.
    expect(await screen.findByRole('alert')).toBeVisible();
    expect(api.calls.map((c) => c.path)).toEqual(['/api/auth/prelogin']);
  });

  it('links to register and recover', () => {
    mockApi({});
    renderRoutes(routes, '/login');
    expect(screen.getByRole('link', { name: 'Create an account' })).toHaveAttribute(
      'href',
      '/register',
    );
    expect(screen.getByRole('link', { name: 'Recover an account' })).toHaveAttribute(
      'href',
      '/recover',
    );
  });
});
