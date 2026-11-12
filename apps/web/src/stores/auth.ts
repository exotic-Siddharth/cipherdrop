/**
 * Session state (spec 11.3 "API client", R22). The access token lives in memory only; the refresh token is the
 * httpOnly `cd_rt` cookie, which this code never sees.
 *
 * - refresh() is single-flight: boot and every 401 share ONE in-flight POST /auth/refresh, and across tabs it
 *   runs under navigator.locks 'cd-refresh' so two tabs never present the same rotating cookie (which the
 *   server would treat as token reuse and revoke the session).
 * - A refresh rejected by the server ends the session with reason 'session-expired' (Review Focus 5).
 * - A session epoch guards against stale results: a refresh that started before a login/logout is ignored.
 * - This store only holds state. The account crypto flows (W1) call setSession() after login/register and
 *   put the account key into the vault store themselves.
 */
import type { AuthSuccess, Me } from '@cipherdrop/shared';
import { OWNER_TOKEN_HEADER, RefreshResponseSchema } from '@cipherdrop/shared';
import { toast } from 'sonner';
import { create } from 'zustand';
import { resetKdfWorker } from '../crypto/kdfClient';
import { takeResumeRecordNotOwnedBy } from '../features/send/resumeRecord';
import { apiUrl } from '../lib/http';
import { queryClient } from '../lib/queryClient';
import { useVault } from './vault';

export type AuthStatus = 'booting' | 'authenticated' | 'anonymous';

/**
 * Why a session ended: 'user' = explicit sign-out (the server session is revoked); 'session-expired' = the
 * refresh was rejected (expired, or revoked on another device); 'account-deleted' = DELETE /me succeeded.
 */
export type LogoutReason = 'user' | 'session-expired' | 'account-deleted';

export type RefreshResult =
  { ok: true } | { ok: false; reason: 'unauthorized' | 'network' | 'server' };

export interface AuthState {
  status: AuthStatus;
  user: Me | null;
  /** JWT access token (15 min). Memory only. */
  accessToken: string | null;
  /** Local-clock time the access token expires (from its own iat/exp lifetime, so clock skew is harmless). */
  accessTokenExpiresAt: number | null;
  /** Why the last session ended; null while signed in or before any session. */
  logoutReason: LogoutReason | null;
  /** Start or replace the session (login, register, MFA, recovery, refresh). */
  setSession: (session: AuthSuccess) => void;
  /** Update the signed-in user (after GET /me or PATCH /me/settings). */
  setUser: (user: Me) => void;
  /** Single-flight silent refresh (boot, 401 retry, proactive). Never throws. */
  refresh: () => Promise<RefreshResult>;
  /** End the session locally (vault locked, query cache cleared); 'user' also revokes it server-side. */
  logout: (reason?: LogoutReason) => Promise<void>;
}

/** Default access-token lifetime when a token cannot be decoded (ACCESS_TOKEN_TTL_SEC default). */
const FALLBACK_TOKEN_LIFETIME_MS = 900_000;

/** exp - iat of a JWT, in ms. Only reads the payload; the server verifies the signature. */
export function tokenLifetimeMs(token: string): number {
  try {
    const payload = token.split('.')[1];
    if (!payload) return FALLBACK_TOKEN_LIFETIME_MS;
    const b64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='))) as {
      iat?: unknown;
      exp?: unknown;
    };
    if (
      typeof claims.iat === 'number' &&
      typeof claims.exp === 'number' &&
      claims.exp > claims.iat
    ) {
      return (claims.exp - claims.iat) * 1000;
    }
  } catch {
    // Not a JWT we can read: use the default lifetime.
  }
  return FALLBACK_TOKEN_LIFETIME_MS;
}

type RefreshOutcome =
  { ok: true; session: AuthSuccess } | { ok: false; reason: 'unauthorized' | 'network' | 'server' };

async function requestRefresh(): Promise<RefreshOutcome> {
  let res: Response;
  try {
    res = await fetch(apiUrl('/auth/refresh'), {
      method: 'POST',
      headers: { accept: 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch {
    return { ok: false, reason: 'network' };
  }
  if (!res.ok) {
    // Any 4xx except 429 means this cookie can no longer refresh; 429/5xx are transient.
    const transient = res.status === 429 || res.status >= 500;
    return { ok: false, reason: transient ? 'server' : 'unauthorized' };
  }
  const parsed = RefreshResponseSchema.safeParse(await res.json().catch(() => null));
  return parsed.success ? { ok: true, session: parsed.data } : { ok: false, reason: 'server' };
}

async function withRefreshLock(run: () => Promise<RefreshOutcome>): Promise<RefreshOutcome> {
  const locks = typeof navigator === 'undefined' ? undefined : navigator.locks;
  // Other tabs share the cd_rt cookie: refresh one tab at a time so a rotated cookie is never replayed.
  if (locks?.request) return await locks.request('cd-refresh', run);
  return run();
}

let inflight: Promise<RefreshResult> | null = null;
/** Bumped on every login/logout so a refresh that started earlier cannot overwrite the newer state. */
let epoch = 0;

function notifySessionEnded(reason: LogoutReason) {
  if (reason === 'session-expired') {
    toast.warning('You were signed out', {
      id: 'session-ended',
      description:
        'Your session expired or was ended on another device. Sign in again to continue.',
    });
  } else if (reason === 'account-deleted') {
    toast.success('Account deleted', {
      id: 'session-ended',
      description: 'Your account, your drops and their files were permanently removed.',
    });
  }
}

/**
 * The interrupted upload of an account that is no longer signed in here is forgotten wherever the session
 * changes, not only on the Send page (C-R4-04), and its drop is deleted best-effort with the owner token.
 */
function forgetResumeNotOwnedBy(ownerId: string | null) {
  const record = takeResumeRecordNotOwnedBy(ownerId);
  if (!record) return;
  void fetch(apiUrl(`/drops/${encodeURIComponent(record.dropId)}`), {
    method: 'DELETE',
    headers: { [OWNER_TOKEN_HEADER]: record.ownerToken },
    credentials: 'same-origin',
    cache: 'no-store',
  }).catch(() => undefined);
}

export const useAuth = create<AuthState>()((set, get) => {
  /** Local part of every logout: forget the token, lock the vault, drop cached (decrypted) data. */
  const endSession = (reason: LogoutReason) => {
    epoch += 1;
    set({
      status: 'anonymous',
      user: null,
      accessToken: null,
      accessTokenExpiresAt: null,
      logoutReason: reason,
    });
    useVault.getState().lock('logout');
    forgetResumeNotOwnedBy(null);
    // A derivation still running would otherwise hand its key to the vault after sign-out.
    resetKdfWorker();
    queryClient.clear();
  };

  return {
    status: 'booting',
    user: null,
    accessToken: null,
    accessTokenExpiresAt: null,
    logoutReason: null,

    setSession: (session) => {
      const previous = get().user;
      if (previous?.id !== session.user.id) {
        // A different account signed in on this page: nothing of the previous one may survive. The vault
        // is locked even with no previous user, so a stale key cannot carry over into a new session.
        if (previous || useVault.getState().accountKey) useVault.getState().lock('logout');
        if (previous) queryClient.clear();
        forgetResumeNotOwnedBy(session.user.id);
      }
      epoch += 1;
      set({
        status: 'authenticated',
        user: session.user,
        accessToken: session.accessToken,
        accessTokenExpiresAt: Date.now() + tokenLifetimeMs(session.accessToken),
        logoutReason: null,
      });
      useVault.getState().setAutoLockMinutes(session.user.autoLockMinutes);
    },

    setUser: (user) => {
      set({ user });
      useVault.getState().setAutoLockMinutes(user.autoLockMinutes);
    },

    refresh: () => {
      if (inflight) return inflight;
      const startedAt = epoch;
      inflight = (async (): Promise<RefreshResult> => {
        const outcome = await withRefreshLock(requestRefresh);
        if (epoch !== startedAt) {
          // A login or logout happened meanwhile: that state wins.
          return outcome.ok ? { ok: true } : { ok: false, reason: outcome.reason };
        }
        if (outcome.ok) {
          get().setSession(outcome.session);
          return { ok: true };
        }
        const { status } = get();
        if (outcome.reason === 'unauthorized') {
          if (status === 'authenticated') {
            endSession('session-expired');
            notifySessionEnded('session-expired');
          } else {
            set({ status: 'anonymous' });
          }
        } else if (status === 'booting') {
          // Server unreachable at boot: continue signed out (the user can sign in once it is back).
          set({ status: 'anonymous' });
        }
        return { ok: false, reason: outcome.reason };
      })().finally(() => {
        inflight = null;
      });
      return inflight;
    },

    logout: async (reason = 'user') => {
      const hadSession = get().status === 'authenticated';
      endSession(reason);
      if (reason !== 'user') {
        notifySessionEnded(reason);
        return;
      }
      if (!hadSession) return;
      try {
        // Revokes the session family and clears the cd_rt cookie (auth: refresh cookie).
        const res = await fetch(apiUrl('/auth/logout'), {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
        });
        if (!res.ok && res.status !== 401) throw new Error(`logout failed (${res.status})`);
      } catch {
        toast.warning('Signed out on this device only', {
          description:
            "We couldn't reach the server to end the session. It ends by itself when it expires.",
        });
      }
    },
  };
});
