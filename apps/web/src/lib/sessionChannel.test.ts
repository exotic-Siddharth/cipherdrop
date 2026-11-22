import type { AuthSuccess } from '@cipherdrop/shared';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startSessionSync, useAuth } from '../stores/auth';
import { lockVaultEverywhere, useVault } from '../stores/vault';
import {
  SESSION_CHANNEL_NAME,
  SESSION_SIGNAL_STORAGE_KEY,
  parseSessionSignal,
  resetSessionChannelForTests,
} from './sessionChannel';

const session: AuthSuccess = {
  user: {
    id: 'u1',
    email: 'u1@example.com',
    role: 'USER',
    totpEnabled: false,
    autoLockMinutes: 15,
    storageQuotaBytes: 1_000_000,
    storageUsedBytes: 0,
    quotaProbationEndsAt: null,
    createdAt: '2026-11-07T10:00:00.000Z',
  },
  accessToken: 'access',
};
const aesKey = () =>
  crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

let stop: (() => void) | undefined;
let otherTab: BroadcastChannel | undefined;

beforeEach(() => {
  resetSessionChannelForTests();
  localStorage.clear();
});

afterEach(() => {
  stop?.();
  stop = undefined;
  otherTab?.close();
  otherTab = undefined;
  resetSessionChannelForTests();
  vi.unstubAllGlobals();
  useAuth.setState(useAuth.getInitialState(), true);
  useVault.setState(useVault.getInitialState(), true);
});

describe('cross-tab lock and sign-out (critic-8)', () => {
  it('a lock in another tab removes the account key here', async () => {
    useVault.getState().setAccountKey(await aesKey());
    stop = startSessionSync();
    otherTab = new BroadcastChannel(SESSION_CHANNEL_NAME);

    otherTab.postMessage({ type: 'lock' });
    await settle();

    expect(useVault.getState()).toMatchObject({ accountKey: null, lockReason: 'manual' });
  });

  it('Lock vault tells the other tabs, with no key material in the signal', async () => {
    useVault.getState().setAccountKey(await aesKey());
    otherTab = new BroadcastChannel(SESSION_CHANNEL_NAME);
    const received: unknown[] = [];
    otherTab.addEventListener('message', (e) => received.push(e.data));

    lockVaultEverywhere();
    await settle();

    expect(useVault.getState().accountKey).toBeNull();
    expect(received).toEqual([{ type: 'lock' }]);
  });

  it('a sign-out in another tab ends the session here, and a sign-out here tells the others', async () => {
    useAuth.getState().setSession(session);
    useVault.getState().setAccountKey(await aesKey());
    stop = startSessionSync();
    otherTab = new BroadcastChannel(SESSION_CHANNEL_NAME);
    const received: unknown[] = [];
    otherTab.addEventListener('message', (e) => received.push(e.data));

    otherTab.postMessage({ type: 'logout', reason: 'user' });
    await settle();

    expect(useAuth.getState()).toMatchObject({ status: 'anonymous', accessToken: null });
    expect(useVault.getState()).toMatchObject({ accountKey: null, lockedSinceBoot: true });
    // The receiving tab does not echo the signal back.
    expect(received).toEqual([]);

    useAuth.getState().setSession(session);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 204 })),
    );
    await useAuth.getState().logout('user');
    await settle();
    expect(received).toEqual([{ type: 'logout', reason: 'user' }]);
  });

  it('falls back to a storage event without BroadcastChannel, leaving nothing in storage', async () => {
    vi.stubGlobal('BroadcastChannel', undefined);
    resetSessionChannelForTests();
    useVault.getState().setAccountKey(await aesKey());
    stop = startSessionSync();

    window.dispatchEvent(
      new StorageEvent('storage', {
        key: SESSION_SIGNAL_STORAGE_KEY,
        newValue: JSON.stringify({ type: 'lock', nonce: 'n' }),
      }),
    );
    expect(useVault.getState().accountKey).toBeNull();

    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    useVault.getState().setAccountKey(await aesKey());
    lockVaultEverywhere();
    expect(setItem).toHaveBeenCalledWith(
      SESSION_SIGNAL_STORAGE_KEY,
      expect.stringContaining('"lock"'),
    );
    expect(localStorage.getItem(SESSION_SIGNAL_STORAGE_KEY)).toBeNull();
  });

  it('ignores malformed signals', () => {
    expect(parseSessionSignal(null)).toBeNull();
    expect(parseSessionSignal('lock')).toBeNull();
    expect(parseSessionSignal({ type: 'logout', reason: 'nope' })).toBeNull();
    expect(parseSessionSignal({ type: 'unlock', key: 'x' })).toBeNull();
    expect(parseSessionSignal({ type: 'lock', key: 'x' })).toEqual({ type: 'lock' });
  });
});
