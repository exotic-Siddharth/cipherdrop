/**
 * Cross-tab session signals (critic-8): "Lock vault" and sign-out apply to every open tab of this browser, not
 * only the tab where the user clicked.
 *
 * - Transport: a BroadcastChannel; where that is missing, a localStorage `storage` event (the signal is written
 *   and removed at once, so nothing stays in storage).
 * - A signal carries only its type (and, for a sign-out, the reason). Never key material: each tab holds its own
 *   account key and simply forgets it.
 * - A tab never receives its own signal, so a receiver that locks locally cannot loop.
 */
import type { LogoutReason } from '../stores/auth';

export type SessionSignal = { type: 'lock' } | { type: 'logout'; reason: LogoutReason };

export const SESSION_CHANNEL_NAME = 'cipherdrop-session';
/** Storage key of the fallback transport; its value is only ever present for an instant. */
export const SESSION_SIGNAL_STORAGE_KEY = 'cd-session-signal';

const LOGOUT_REASONS: readonly LogoutReason[] = ['user', 'session-expired', 'account-deleted'];

/** Parse an untrusted message (another tab, or anything else writing to the channel or the key). */
export function parseSessionSignal(data: unknown): SessionSignal | null {
  if (!data || typeof data !== 'object') return null;
  const { type, reason } = data as { type?: unknown; reason?: unknown };
  if (type === 'lock') return { type: 'lock' };
  if (type === 'logout' && LOGOUT_REASONS.includes(reason as LogoutReason)) {
    return { type: 'logout', reason: reason as LogoutReason };
  }
  return null;
}

let channel: BroadcastChannel | null | undefined;

function getChannel(): BroadcastChannel | null {
  if (channel === undefined) {
    channel =
      typeof BroadcastChannel === 'function' ? new BroadcastChannel(SESSION_CHANNEL_NAME) : null;
  }
  return channel;
}

/** Tell the other tabs of this browser to lock their vault or end their session. Never throws. */
export function broadcastSessionSignal(signal: SessionSignal): void {
  try {
    const ch = getChannel();
    if (ch) {
      ch.postMessage(signal);
      return;
    }
    if (typeof localStorage === 'undefined') return;
    // The nonce makes every write a change, so repeating the same signal still fires the event.
    localStorage.setItem(
      SESSION_SIGNAL_STORAGE_KEY,
      JSON.stringify({ ...signal, nonce: crypto.randomUUID() }),
    );
    localStorage.removeItem(SESSION_SIGNAL_STORAGE_KEY);
  } catch {
    // Best effort: the other tabs still lock on idle and heal on their next API call.
  }
}

/** Receive the signals other tabs send. Returns a stop function. */
export function onSessionSignal(handler: (signal: SessionSignal) => void): () => void {
  const ch = getChannel();
  if (ch) {
    const onMessage = (e: MessageEvent) => {
      const signal = parseSessionSignal(e.data);
      if (signal) handler(signal);
    };
    ch.addEventListener('message', onMessage);
    return () => ch.removeEventListener('message', onMessage);
  }
  const onStorage = (e: StorageEvent) => {
    if (e.key !== SESSION_SIGNAL_STORAGE_KEY || !e.newValue) return;
    let data: unknown;
    try {
      data = JSON.parse(e.newValue);
    } catch {
      return;
    }
    const signal = parseSessionSignal(data);
    if (signal) handler(signal);
  };
  window.addEventListener('storage', onStorage);
  return () => window.removeEventListener('storage', onStorage);
}

/** Tests only: forget the cached channel (e.g. after stubbing BroadcastChannel away). */
export function resetSessionChannelForTests(): void {
  channel?.close();
  channel = undefined;
}
