/**
 * The vault: the account key AK as a NON-EXTRACTABLE AES-GCM CryptoKey, held in memory only (spec 7.5, R7).
 *
 * - Never persisted: this store has no persist middleware and never touches Web Storage, IndexedDB or cookies.
 *   A reload therefore always starts locked.
 * - Flows that need raw AK bytes (password change, recovery-key rotation) re-derive them from the password the
 *   user types, transiently; they never read them from here (R7).
 * - Auto-lock: startVaultAutoLock() locks after `autoLockMinutes` without user activity. Locking in place never
 *   navigates: pages react to `accountKey === null` (dashboard rows show "Locked", Send shows an inline unlock).
 * - The only redirect to /unlock is the boot case (see shouldRedirectToUnlock).
 */
import type { AutoLockMinutes } from '@cipherdrop/shared';
import { DEFAULT_AUTO_LOCK_MINUTES } from '@cipherdrop/shared';
import { create } from 'zustand';

export type VaultLockReason = 'idle' | 'manual' | 'logout';

export interface VaultState {
  /** AK as a non-extractable AES-GCM key (wrap/unwrap owner keys with AAD "cipherdrop/v1/wrap/owner"). */
  accountKey: CryptoKey | null;
  /** When the vault was last unlocked (ms), null while locked. */
  unlockedAt: number | null;
  /** Last user activity while unlocked (ms), null while locked. */
  lastActivityAt: number | null;
  /** From the user's settings (Me.autoLockMinutes); the auth store keeps it in sync. */
  autoLockMinutes: AutoLockMinutes;
  /** Why the vault last locked; null if it was never unlocked in this session. */
  lockReason: VaultLockReason | null;
  /**
   * True until the first unlock of this page lifetime (and again after a logout). R7: only this boot state
   * redirects vault-needing routes to /unlock; an in-place lock never navigates.
   */
  lockedSinceBoot: boolean;
  /** Store AK. Throws unless the key is a non-extractable AES-GCM CryptoKey. */
  setAccountKey: (key: CryptoKey) => void;
  /** Forget AK (default reason 'manual'). 'logout' also returns to the boot state. */
  lock: (reason?: VaultLockReason) => void;
  /** Record user activity (postpones auto-lock). No-op while locked. */
  touch: () => void;
  setAutoLockMinutes: (minutes: AutoLockMinutes) => void;
}

export const useVault = create<VaultState>()((set, get) => ({
  accountKey: null,
  unlockedAt: null,
  lastActivityAt: null,
  autoLockMinutes: DEFAULT_AUTO_LOCK_MINUTES,
  lockReason: null,
  lockedSinceBoot: true,

  setAccountKey: (key) => {
    if (typeof CryptoKey === 'undefined' || !(key instanceof CryptoKey)) {
      throw new TypeError('The vault only accepts a CryptoKey');
    }
    if (key.algorithm.name !== 'AES-GCM') {
      throw new TypeError('The vault only accepts an AES-GCM key');
    }
    if (key.extractable) {
      throw new TypeError('The vault only accepts a non-extractable key');
    }
    const now = Date.now();
    set({
      accountKey: key,
      unlockedAt: now,
      lastActivityAt: now,
      lockReason: null,
      lockedSinceBoot: false,
    });
  },

  lock: (reason = 'manual') => {
    set({
      accountKey: null,
      unlockedAt: null,
      lastActivityAt: null,
      lockReason: reason,
      lockedSinceBoot: reason === 'logout' ? true : get().lockedSinceBoot,
    });
  },

  touch: () => {
    if (get().accountKey) set({ lastActivityAt: Date.now() });
  },

  setAutoLockMinutes: (minutes) => set({ autoLockMinutes: minutes }),
}));

/** True when the vault holds the account key. */
export function isVaultUnlocked(state: Pick<VaultState, 'accountKey'> = useVault.getState()) {
  return state.accountKey !== null;
}

/** R7: redirect a vault-needing route to /unlock?next= only on a boot (or a fresh session) with no key. */
export function shouldRedirectToUnlock(
  state: Pick<VaultState, 'accountKey' | 'lockedSinceBoot'> = useVault.getState(),
): boolean {
  return state.accountKey === null && state.lockedSinceBoot;
}

/** Events that count as user activity for the idle timer. */
export const VAULT_ACTIVITY_EVENTS = [
  'pointerdown',
  'keydown',
  'wheel',
  'touchstart',
  'mousemove',
] as const;

/** Activity is sampled at most this often (keeps mousemove cheap). */
const ACTIVITY_SAMPLE_MS = 5_000;

/**
 * Install the idle auto-lock (call once at boot; returns a stop function). Checks every `checkEveryMs` and
 * whenever the tab becomes visible again, so throttled background timers and sleep/wake cannot skip it.
 */
export function startVaultAutoLock(target: Window = window, checkEveryMs = 15_000): () => void {
  let lastSample = 0;
  const onActivity = () => {
    const now = Date.now();
    if (now - lastSample < ACTIVITY_SAMPLE_MS) return;
    lastSample = now;
    useVault.getState().touch();
  };
  const check = () => {
    const s = useVault.getState();
    if (!s.accountKey || s.lastActivityAt === null) return;
    if (Date.now() - s.lastActivityAt >= s.autoLockMinutes * 60_000) s.lock('idle');
  };
  const onVisibility = () => {
    if (target.document.visibilityState === 'visible') check();
  };

  for (const type of VAULT_ACTIVITY_EVENTS) {
    target.addEventListener(type, onActivity, { capture: true, passive: true });
  }
  target.document.addEventListener('visibilitychange', onVisibility);
  const timer = target.setInterval(check, checkEveryMs);

  return () => {
    for (const type of VAULT_ACTIVITY_EVENTS) {
      target.removeEventListener(type, onActivity, { capture: true });
    }
    target.document.removeEventListener('visibilitychange', onVisibility);
    target.clearInterval(timer);
  };
}
