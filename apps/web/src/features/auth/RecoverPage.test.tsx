import {
  AAD,
  createAccountBundle,
  deriveAccountKeys,
  KDF_MIN,
  unwrapKey,
} from '@cipherdrop/crypto';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';
import {
  apiError,
  authSuccess,
  installInProcessKdfWorker,
  mockApi,
  renderRoutes,
  resetStores,
} from '../account/testkit';
import { Component as RecoverPage } from './RecoverPage';

const routes = [
  { path: '/recover', Component: RecoverPage },
  { path: '/login', element: <p>login page</p> },
  { path: '/dashboard', element: <p>dashboard page</p> },
];

let bundle: Awaited<ReturnType<typeof createAccountBundle>>;
beforeAll(async () => {
  bundle = await createAccountBundle('the old password 123', KDF_MIN);
});
beforeEach(() => {
  resetStores();
  installInProcessKdfWorker();
});
afterEach(() => resetStores());

describe('RecoverPage', () => {
  it('recovers with the recovery key, sets a new password and shows the replacement key', async () => {
    const api = mockApi({
      'POST /api/auth/recovery/start': {
        json: {
          recoveryToken: 'recovery-token',
          wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
          mfaRequired: false,
        },
      },
      'POST /api/auth/recovery/complete': { json: authSuccess() },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/recover');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Recovery key'), bundle.recoveryKey.toLowerCase());
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    await user.type(await screen.findByLabelText('New password'), 'a brand new passphrase 42');
    await user.type(screen.getByLabelText('Confirm new password'), 'a brand new passphrase 42');
    expect(screen.queryByLabelText(/two-factor/i)).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Set new password' }));

    expect(
      await screen.findByText('Save your new recovery key', {}, { timeout: 15_000 }),
    ).toBeVisible();
    const start = api.calls[0]?.body as { recoveryAuthKey: string };
    expect(start.recoveryAuthKey).toHaveLength(43);
    expect(JSON.stringify(start)).not.toContain(bundle.recoveryKey);

    const complete = api.calls[1]?.body as {
      recoveryToken: string;
      newAuthKey: string;
      kdf: typeof bundle.kdf;
      wrappedAccountKey: string;
      wrappedAccountKeyRecovery: string;
    };
    expect(complete.recoveryToken).toBe('recovery-token');
    expect(complete.wrappedAccountKeyRecovery).not.toBe(bundle.wrappedAccountKeyRecovery);
    // The same AK is now wrapped under the NEW password.
    const { encKey } = await deriveAccountKeys('a brand new passphrase 42', complete.kdf);
    expect(await unwrapKey(encKey, complete.wrappedAccountKey, AAD.WRAP_ACCOUNT)).toEqual(
      bundle.accountKey,
    );
    expect(useAuth.getState().status).toBe('authenticated');
    expect(useVault.getState().accountKey?.extractable).toBe(false);

    const rows = screen.getAllByTestId('recovery-key-row').map((r) => r.textContent);
    expect(rows.join('-')).not.toBe(bundle.recoveryKey);
    await user.click(screen.getByLabelText('I saved my recovery key'));
    await user.click(screen.getByRole('button', { name: /continue to my files/i }));
    expect(await screen.findByText('dashboard page')).toBeVisible();
  }, 40_000);

  it('asks for the two-factor code when the account has 2FA', async () => {
    mockApi({
      'POST /api/auth/recovery/start': {
        json: {
          recoveryToken: 'recovery-token',
          wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
          mfaRequired: true,
        },
      },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/recover');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Recovery key'), bundle.recoveryKey);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByLabelText('Two-factor or backup code')).toBeVisible();
  });

  it('rejects a malformed recovery key locally and a wrong one generically', async () => {
    const api = mockApi({
      'POST /api/auth/recovery/start': apiError(401, 'UNAUTHORIZED', 'Invalid'),
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/recover');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Recovery key'), 'ABCD-1234');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /does not look like a recovery key/i,
    );
    expect(api.fetchMock).not.toHaveBeenCalled();

    await user.clear(screen.getByLabelText('Recovery key'));
    await user.type(screen.getByLabelText('Recovery key'), bundle.recoveryKey);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText(/do not match an account/i)).toBeVisible();
  });
});
