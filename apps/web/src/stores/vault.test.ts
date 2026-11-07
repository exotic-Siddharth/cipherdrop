import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { shouldRedirectToUnlock, startVaultAutoLock, useVault } from './vault';

async function accountKey(extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    crypto.getRandomValues(new Uint8Array(32)),
    'AES-GCM',
    extractable,
    ['encrypt', 'decrypt'],
  );
}

beforeEach(() => {
  useVault.setState(useVault.getInitialState());
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('vault store (memory only, R7)', () => {
  it('lock clears key and is never written to storage', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const key = await accountKey();

    useVault.getState().setAccountKey(key);
    expect(useVault.getState().accountKey).toBe(key);
    expect(useVault.getState().unlockedAt).toEqual(expect.any(Number));
    useVault.getState().touch();
    useVault.getState().setAutoLockMinutes(5);

    useVault.getState().lock('manual');

    expect(useVault.getState()).toMatchObject({
      accountKey: null,
      unlockedAt: null,
      lastActivityAt: null,
      lockReason: 'manual',
    });
    // Nothing about the vault is ever persisted: no Web Storage writes, no cookies.
    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe('');
  });

  it('refuses an extractable or non-AES-GCM key', async () => {
    await expect(accountKey(true)).resolves.toBeDefined();
    const extractable = await accountKey(true);
    expect(() => useVault.getState().setAccountKey(extractable)).toThrow(/non-extractable/i);

    const hmac = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(32),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    expect(() => useVault.getState().setAccountKey(hmac)).toThrow(/AES-GCM/);
    expect(useVault.getState().accountKey).toBeNull();
  });

  it('auto-locks after the idle timeout, and activity postpones it', async () => {
    const key = await accountKey();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-07T12:00:00Z'));
    const stop = startVaultAutoLock(window, 1_000);
    try {
      useVault.getState().setAutoLockMinutes(5);
      useVault.getState().setAccountKey(key);

      vi.advanceTimersByTime(4 * 60_000);
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }));
      vi.advanceTimersByTime(4 * 60_000);
      expect(useVault.getState().accountKey).toBe(key);

      vi.advanceTimersByTime(60_000 + 2_000);
      expect(useVault.getState().accountKey).toBeNull();
      expect(useVault.getState().lockReason).toBe('idle');
    } finally {
      stop();
    }
  });

  it('redirects to /unlock only on a boot with no key, never after an in-place lock', async () => {
    expect(shouldRedirectToUnlock(useVault.getState())).toBe(true);

    useVault.getState().setAccountKey(await accountKey());
    expect(shouldRedirectToUnlock(useVault.getState())).toBe(false);

    useVault.getState().lock('idle');
    expect(shouldRedirectToUnlock(useVault.getState())).toBe(false);

    // A new session starts from the boot state again.
    useVault.getState().lock('logout');
    expect(shouldRedirectToUnlock(useVault.getState())).toBe(true);
  });
});
