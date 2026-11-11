import {
  AAD,
  b64urlEncode,
  createAccountBundle,
  deriveAccountKeys,
  KDF_MIN,
  unwrapKey,
} from '@cipherdrop/crypto';
import type { AuditEventDto, SessionInfo } from '@cipherdrop/shared';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { useAuth } from '../../stores/auth';
import {
  apiError,
  installInProcessKdfWorker,
  mockApi,
  renderRoutes,
  resetStores,
  signIn,
  TEST_ME,
} from '../account/testkit';
import { Component as SettingsPage } from './SettingsPage';

const PASSWORD = 'correct horse battery staple';
let bundle: Awaited<ReturnType<typeof createAccountBundle>>;
const vaultJson = () => ({ wrappedAccountKey: bundle.wrappedAccountKey, kdf: bundle.kdf });

beforeAll(async () => {
  bundle = await createAccountBundle(PASSWORD, KDF_MIN);
});

const routes = [
  { path: '/settings', Component: SettingsPage },
  { path: '/', element: <p>home page</p> },
];

beforeEach(() => {
  resetStores();
  installInProcessKdfWorker();
  signIn();
});
afterEach(() => resetStores());

const sessionFixture = (over: Partial<SessionInfo>): SessionInfo => ({
  id: 'sess_1',
  current: false,
  userAgent: 'Firefox on Linux',
  ipPrefix: '198.51.100.0/24',
  createdAt: '2026-11-07T09:00:00.000Z',
  lastUsedAt: '2026-11-08T08:00:00.000Z',
  expiresAt: '2026-12-07T09:00:00.000Z',
  ...over,
});

const auditFixture = (n: number, action: AuditEventDto['action']): AuditEventDto => ({
  id: `evt_${n}`,
  action,
  dropId: null,
  ipPrefix: '203.0.113.0/24',
  userAgent: 'Chrome on Windows',
  metadata: null,
  createdAt: '2026-11-08T07:00:00.000Z',
});

describe('SettingsPage security tab', () => {
  it('sets up TOTP with a QR code and manual secret, shows backup codes once', async () => {
    const api = mockApi({
      'POST /api/auth/mfa/totp/setup': {
        json: {
          secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
          otpauthUrl:
            'otpauth://totp/CipherDrop:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=CipherDrop',
        },
      },
      'POST /api/auth/mfa/totp/enable': {
        json: { backupCodes: Array.from({ length: 10 }, (_, i) => `abcd${i}-efgh${i}`) },
      },
      'GET /api/me': { json: { user: { ...TEST_ME, totpEnabled: true } } },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings');
    await user.click(screen.getByRole('button', { name: 'Set up two-step verification' }));

    expect(
      await screen.findByRole('img', { name: /QR code for your authenticator app/i }),
    ).toBeVisible();
    expect(screen.getByDisplayValue('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')).toBeVisible();

    await user.type(screen.getByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify and turn on' }));

    const list = await screen.findByRole('list', { name: 'Backup codes' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(10);
    expect(api.calls.find((c) => c.path === '/api/auth/mfa/totp/enable')?.body).toEqual({
      code: '123456',
    });
    // 2FA is now on, but the codes stay on screen until the user confirms they saved them.
    expect(useAuth.getState().user?.totpEnabled).toBe(true);
    const done = screen.getByRole('button', { name: 'Done' });
    expect(done).toBeDisabled();
    await user.click(screen.getByLabelText('I saved my backup codes'));
    await user.click(done);
    expect(screen.queryByRole('list', { name: 'Backup codes' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Regenerate backup codes' })).toBeVisible();
  });

  it('turns TOTP off with a password-derived proof, not the password', async () => {
    signIn({ totpEnabled: true });
    const api = mockApi({
      'GET /api/auth/vault': { json: vaultJson() },
      'POST /api/auth/mfa/totp/disable': { status: 204 },
      'GET /api/me': { json: { user: { ...TEST_ME, totpEnabled: false } } },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings');
    await user.click(screen.getByRole('button', { name: 'Turn off' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText('Your password'), PASSWORD);
    await user.type(within(dialog).getByLabelText('Two-factor or backup code'), '654321');
    await user.click(within(dialog).getByRole('button', { name: 'Turn off' }));

    await waitFor(() => expect(useAuth.getState().user?.totpEnabled).toBe(false));
    const body = api.calls.find((c) => c.path === '/api/auth/mfa/totp/disable')?.body as {
      authKey: string;
      code: string;
    };
    expect(body.authKey).toBe(b64urlEncode(bundle.authKey));
    expect(body.code).toBe('654321');
    expect(JSON.stringify(body)).not.toContain(PASSWORD);
  });

  it('rejects a wrong current password locally, without POST /auth/password', async () => {
    const api = mockApi({ 'GET /api/auth/vault': { json: vaultJson() } });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings');
    await user.type(screen.getByLabelText('Current password'), 'not my password');
    await user.type(screen.getByLabelText('New password'), 'a brand new passphrase 42');
    await user.type(screen.getByLabelText('Confirm new password'), 'a brand new passphrase 42');
    await user.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('Your current password is incorrect.')).toBeVisible();
    expect(api.calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /api/auth/vault']);
  });

  it('changes the password: re-wraps the same account key and sends only derived values', async () => {
    const api = mockApi({
      'GET /api/auth/vault': { json: vaultJson() },
      'POST /api/auth/password': { status: 204 },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings');
    await user.type(screen.getByLabelText('Current password'), PASSWORD);
    await user.type(screen.getByLabelText('New password'), 'a brand new passphrase 42');
    await user.type(screen.getByLabelText('Confirm new password'), 'a brand new passphrase 42');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    await waitFor(() => expect(api.calls.some((c) => c.path === '/api/auth/password')).toBe(true));
    const body = api.calls.find((c) => c.path === '/api/auth/password')?.body as {
      currentAuthKey: string;
      newAuthKey: string;
      kdf: typeof bundle.kdf;
      wrappedAccountKey: string;
    };
    expect(body.currentAuthKey).toBe(b64urlEncode(bundle.authKey));
    const { encKey } = await deriveAccountKeys('a brand new passphrase 42', body.kdf);
    expect(await unwrapKey(encKey, body.wrappedAccountKey, AAD.WRAP_ACCOUNT)).toEqual(
      bundle.accountKey,
    );
    expect(JSON.stringify(body)).not.toContain('passphrase');
    expect(await screen.findByLabelText('Current password')).toHaveValue('');
  });

  it('replaces the recovery key and shows the new one on the recovery card', async () => {
    const api = mockApi({
      'GET /api/auth/vault': { json: vaultJson() },
      'POST /api/auth/recovery/rotate': { status: 204 },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings');
    await user.click(screen.getByRole('button', { name: 'Replace recovery key' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText('Your password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Create new key' }));

    expect(await screen.findByText('Save your new recovery key')).toBeVisible();
    const body = api.calls.find((c) => c.path === '/api/auth/recovery/rotate')?.body as Record<
      string,
      string
    >;
    expect(body.authKey).toBe(b64urlEncode(bundle.authKey));
    expect(body).not.toHaveProperty('code');
    expect(body.wrappedAccountKeyRecovery).not.toBe(bundle.wrappedAccountKeyRecovery);
    // Sensitive calls must not trigger a token refresh loop (R22).
    expect(api.calls.filter((c) => c.path === '/api/auth/refresh')).toHaveLength(0);
  });

  it('saves the auto-lock choice', async () => {
    const api = mockApi({
      'PATCH /api/me/settings': { json: { user: { ...TEST_ME, autoLockMinutes: 5 } } },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings');
    await user.selectOptions(screen.getByLabelText('Lock the vault'), '5');
    await waitFor(() => expect(useAuth.getState().user?.autoLockMinutes).toBe(5));
    expect(api.calls[0]?.body).toEqual({ autoLockMinutes: 5 });
  });
});

describe('SettingsPage sessions tab', () => {
  it('marks the current session and signs out all others', async () => {
    let revoked = false;
    const api = mockApi({
      'GET /api/auth/sessions': () => ({
        json: revoked
          ? [sessionFixture({ id: 'cur', current: true, userAgent: 'Chrome on Windows' })]
          : [
              sessionFixture({ id: 'cur', current: true, userAgent: 'Chrome on Windows' }),
              sessionFixture({ id: 'other', userAgent: 'Safari on iPhone' }),
            ],
      }),
      'POST /api/auth/sessions/revoke-others': () => {
        revoked = true;
        return { status: 204 };
      },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings?tab=sessions');
    expect(await screen.findByText('Chrome on Windows')).toBeVisible();
    expect(screen.getByText('This device')).toBeVisible();
    expect(screen.getByText('Safari on iPhone')).toBeVisible();
    // Only the other session has its own sign-out button.
    expect(screen.getByRole('button', { name: 'Sign out Safari on iPhone' })).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Sign out all others' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Sign out all others' }));
    await waitFor(() => expect(screen.queryByText('Safari on iPhone')).toBeNull());
    expect(api.calls.some((c) => c.path === '/api/auth/sessions/revoke-others')).toBe(true);
  });

  it('revokes one session', async () => {
    const api = mockApi({
      'GET /api/auth/sessions': {
        json: [
          sessionFixture({ id: 'cur', current: true }),
          sessionFixture({ id: 'other_1', userAgent: 'Safari on iPhone' }),
        ],
      },
      'DELETE /api/auth/sessions/other_1': { status: 204 },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings?tab=sessions');
    await user.click(await screen.findByRole('button', { name: 'Sign out Safari on iPhone' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Sign out' }));
    await waitFor(() =>
      expect(
        api.calls.some((c) => c.method === 'DELETE' && c.path === '/api/auth/sessions/other_1'),
      ).toBe(true),
    );
  });
});

describe('SettingsPage activity tab', () => {
  it('shows human labels, filters by action and paginates', async () => {
    const api = mockApi({
      'GET /api/me/audit': (call) => {
        const action = call.query.get('action');
        const page = Number(call.query.get('page') ?? '1');
        const items =
          action === 'PASSWORD_CHANGED'
            ? [auditFixture(99, 'PASSWORD_CHANGED')]
            : [
                auditFixture(page * 10, 'LOGIN_SUCCESS'),
                auditFixture(page * 10 + 1, 'DROP_OPENED'),
              ];
        return { json: { items, total: action ? 1 : 45, page, pageSize: 20 } };
      },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings?tab=activity');
    expect(await screen.findByText('Signed in', { selector: 'p' })).toBeVisible();
    expect(screen.getByText('Your drop was downloaded', { selector: 'p' })).toBeVisible();
    expect(screen.getAllByText(/203\.0\.113\.0\/24/).length).toBeGreaterThan(0);

    await user.click(screen.getByRole('button', { name: /next/i }));
    await waitFor(() => expect(api.calls.some((c) => c.query.get('page') === '2')).toBe(true));

    await user.selectOptions(screen.getByLabelText('Show'), 'PASSWORD_CHANGED');
    expect(await screen.findByText('Password changed', { selector: 'p' })).toBeVisible();
    const last = api.calls.at(-1);
    expect(last?.query.get('action')).toBe('PASSWORD_CHANGED');
    expect(last?.query.get('page')).toBe('1');
  });

  it('shows an empty state', async () => {
    mockApi({ 'GET /api/me/audit': { json: { items: [], total: 0, page: 1, pageSize: 20 } } });
    renderRoutes(routes, '/settings?tab=activity');
    expect(await screen.findByText('Nothing here yet')).toBeVisible();
  });

  it('shows an error state with retry', async () => {
    mockApi({ 'GET /api/me/audit': apiError(403, 'FORBIDDEN', 'Nope') });
    renderRoutes(routes, '/settings?tab=activity');
    expect(await screen.findByText('We could not load your activity')).toBeVisible();
    expect(screen.getByRole('button', { name: /try again|retry/i })).toBeVisible();
  });
});

describe('SettingsPage account tab', () => {
  it('delete needs the typed phrase, the password and (when on) the 2FA code', async () => {
    signIn({ totpEnabled: true });
    const api = mockApi({
      'GET /api/auth/vault': { json: vaultJson() },
      'DELETE /api/me': { status: 204 },
      'POST /api/auth/logout': { status: 204 },
    });
    const user = userEvent.setup();
    renderRoutes(routes, '/settings?tab=account');
    await user.click(screen.getByRole('button', { name: /delete my account/i }));
    const dialog = await screen.findByRole('dialog');
    const confirmBtn = within(dialog).getByRole('button', { name: 'Delete everything' });
    expect(confirmBtn).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/type delete to confirm/i), 'DELETE');
    expect(confirmBtn).toBeEnabled();
    await user.type(within(dialog).getByLabelText('Your password'), PASSWORD);
    await user.type(within(dialog).getByLabelText('Two-factor or backup code'), '123456');
    await user.click(confirmBtn);

    expect(await screen.findByText('home page')).toBeVisible();
    const del = api.calls.find((c) => c.method === 'DELETE' && c.path === '/api/me')
      ?.body as Record<string, string>;
    expect(del.authKey).toBe(b64urlEncode(bundle.authKey));
    expect(del.code).toBe('123456');
    expect(JSON.stringify(del)).not.toContain(PASSWORD);
    expect(useAuth.getState().status).toBe('anonymous');
    expect(useAuth.getState().logoutReason).toBe('account-deleted');
  });

  it('shows the profile and the storage meter', () => {
    mockApi({});
    renderRoutes(routes, '/settings?tab=account');
    expect(screen.getByText('ada@example.com')).toBeVisible();
    expect(screen.getByRole('progressbar', { name: 'Storage used' })).toBeVisible();
  });
});

describe('SettingsPage tabs', () => {
  it('syncs the selected tab to ?tab= and defaults to security', async () => {
    mockApi({ 'GET /api/auth/sessions': { json: [sessionFixture({ current: true })] } });
    const user = userEvent.setup();
    const router = renderRoutes(routes, '/settings?tab=bogus');
    expect(screen.getByRole('tab', { name: /security/i })).toHaveAttribute('aria-selected', 'true');
    await user.click(screen.getByRole('tab', { name: /sessions/i }));
    expect(router.state.location.search).toBe('?tab=sessions');
  });
});
