import type { AuthSuccess, Me } from '@cipherdrop/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kdfClient, resetKdfWorker } from '../crypto/kdfClient';
import { queryClient } from '../lib/queryClient';
import { useAuth } from './auth';
import { useVault } from './vault';

const me = (id: string): Me => ({
  id,
  email: `${id}@example.com`,
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 1_000_000,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
});
const session = (id: string): AuthSuccess => ({ user: me(id), accessToken: 'access' });
const aesKey = () =>
  crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);

/** A worker that never answers, like Argon2id still running. */
class HangingWorker {
  addEventListener() {}
  removeEventListener() {}
  terminate() {}
  postMessage() {}
}

afterEach(() => {
  vi.unstubAllGlobals();
  resetKdfWorker();
  useAuth.setState(useAuth.getInitialState(), true);
  useVault.setState(useVault.getInitialState(), true);
  queryClient.clear();
});

describe('auth store', () => {
  it('a new session never inherits an unlocked vault from before it (C-36)', async () => {
    useVault.getState().setAccountKey(await aesKey());
    useAuth.getState().setSession(session('user_b'));
    expect(useVault.getState().accountKey).toBeNull();
  });

  it('a refresh of the same user keeps the vault unlocked', async () => {
    useAuth.getState().setSession(session('user_a'));
    useVault.getState().setAccountKey(await aesKey());
    useAuth.getState().setSession(session('user_a'));
    expect(useVault.getState().accountKey).not.toBeNull();
  });

  it('signing out cancels a key derivation that is still running (C-36)', async () => {
    vi.stubGlobal('Worker', HangingWorker);
    resetKdfWorker();
    useAuth.getState().setSession(session('user_a'));
    const pending = kdfClient.deriveAccountKeys('a password', {
      salt: 'AAAAAAAAAAAAAAAAAAAAAA',
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
    });
    const settled = expect(pending).rejects.toThrow(/cancelled/);
    await useAuth.getState().logout('session-expired');
    await settled;
  });
});
