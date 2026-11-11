import { AAD, importAesKey, randomBytes, wrapKey } from '@cipherdrop/crypto';
import type { Me } from '@cipherdrop/shared';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kdfClient } from '../../../crypto/kdfClient';
import { queryClient } from '../../../lib/queryClient';
import { useAuth } from '../../../stores/auth';
import { useVault } from '../../../stores/vault';
import { VaultUnlockInline } from './VaultUnlockInline';

const encKey = await importAesKey(randomBytes(32));
const wrappedAccountKey = await wrapKey(encKey, randomBytes(32), AAD.WRAP_ACCOUNT);

vi.mock('../../../crypto/kdfClient', () => ({
  kdfClient: { deriveAccountKeys: vi.fn(async () => ({ encKey, authKey: new Uint8Array(32) })) },
  resetKdfWorker: vi.fn(),
}));

const me: Me = {
  id: 'user_1',
  email: 'ada@example.com',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 1_000_000,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
};

afterEach(() => {
  vi.unstubAllGlobals();
  useAuth.setState(useAuth.getInitialState(), true);
  useVault.setState(useVault.getInitialState(), true);
  queryClient.clear();
});

describe('VaultUnlockInline', () => {
  it('discards the unlocked key when the user signed out while it was working (C-36)', async () => {
    useAuth.setState({ status: 'authenticated', user: me, accessToken: 'access' });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        await gate;
        return new Response(
          JSON.stringify({
            wrappedAccountKey,
            kdf: {
              salt: 'AAAAAAAAAAAAAAAAAAAAAA',
              memoryKiB: 65536,
              iterations: 3,
              parallelism: 1,
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }),
    );
    render(
      <MemoryRouter>
        <VaultUnlockInline />
      </MemoryRouter>,
    );
    await userEvent.type(screen.getByPlaceholderText('Account password'), 'correct horse');
    await userEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    await useAuth.getState().logout('session-expired');
    release();
    await waitFor(() => expect(kdfClient.deriveAccountKeys).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 100)); // let unwrap + import settle
    expect(useVault.getState().accountKey).toBeNull();
  });
});
