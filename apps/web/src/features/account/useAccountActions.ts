/**
 * Account flows (spec 7.5, 10): register, login (+ MFA), unlock, password change, recovery, recovery-key
 * rotation, TOTP disable and account deletion. Key derivation always runs in kdf.worker via kdfClient.
 *
 * Zero-knowledge rules kept here:
 * - the server only ever receives HKDF-derived auth keys and keys wrapped in the browser, never a password;
 * - the vault gets AK as a NON-extractable CryptoKey (R7); flows that need the raw AK re-derive it from the
 *   password the user just typed, inside the worker, and zero it (changePassword, rotateRecoveryKey);
 * - password-verifying calls pass skipRefresh: true (R22) so a wrong password cannot trigger a token refresh loop.
 */
import { AAD, b64urlEncode, importAesKey, unwrapKey, type KdfParams } from '@cipherdrop/crypto';
import {
  AuthSuccessSchema,
  BackupCodesResponseSchema,
  LoginResponseSchema,
  MeResponseSchema,
  PreloginResponseSchema,
  RecoveryStartResponseSchema,
  TotpSetupResponseSchema,
  VaultSchema,
  type AuthSuccess,
  type BackupCodesResponse,
  type Me,
  type TotpSetupResponse,
  type Vault,
} from '@cipherdrop/shared';
import { useMemo, useRef } from 'react';
import { useNavigate } from 'react-router';
import { useSignOut } from '../../components/layout/useSignOut';
import { kdfClient } from '../../crypto/kdfClient';
import { api } from '../../lib/api';
import { queryClient, queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';

export interface LoginResult {
  mfaRequired: boolean;
}

export interface AccountActions {
  /** Create the account: derive keys locally, register, unlock the vault. Returns the recovery key to show once. */
  register(email: string, password: string): Promise<{ recoveryKey: string }>;
  /** Prelogin, derive, login. `mfaRequired` means completeMfa(code) must follow. */
  login(email: string, password: string): Promise<LoginResult>;
  completeMfa(code: string): Promise<void>;
  /** Forget a pending MFA step (the "Back" button). */
  cancelMfa(): void;
  /** Local unwrap of the account key with the typed password. A wrong password never touches the network. */
  unlock(password: string): Promise<void>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  /** R9: new recovery key for the same AK. `code` is the TOTP/backup code when 2FA is enabled. */
  rotateRecoveryKey(password: string, code?: string): Promise<{ recoveryKey: string }>;
  /** Step 1 of /recover: prove possession of the recovery key. */
  startRecovery(email: string, recoveryKey: string): Promise<{ mfaRequired: boolean }>;
  /** Step 2 of /recover: set the new password. Returns the replacement recovery key to show once. */
  completeRecovery(newPassword: string, code?: string): Promise<{ newRecoveryKey: string }>;
  setupTotp(): Promise<TotpSetupResponse>;
  enableTotp(code: string): Promise<BackupCodesResponse>;
  regenerateBackupCodes(code: string): Promise<BackupCodesResponse>;
  disableTotp(password: string, code: string): Promise<void>;
  /** DELETE /me, then leaves for the home page and ends the session with reason 'account-deleted'. */
  deleteAccount(password: string, code?: string): Promise<void>;
  /** Navigates home first, then revokes the session and locks the vault. */
  logout(): Promise<void>;
}

/** The server's current kdf params and wrapped AK, always fresh (they change with every password change). */
async function fetchVault(): Promise<Vault> {
  return queryClient.fetchQuery({
    queryKey: queryKeys.vault(),
    queryFn: () => api.get('/auth/vault', { schema: VaultSchema }),
    staleTime: 0,
  });
}

async function authKeyFor(password: string, kdf: KdfParams): Promise<string> {
  const { authKey } = await kdfClient.deriveAccountKeys(password, kdf);
  return b64urlEncode(authKey);
}

/** Unwrap AK with encKey and hand it to the vault as a non-extractable key; the raw bytes are zeroed. */
async function openVault(encKey: CryptoKey, wrappedAccountKey: string): Promise<void> {
  const raw = await unwrapKey(encKey, wrappedAccountKey, AAD.WRAP_ACCOUNT);
  try {
    useVault.getState().setAccountKey(await importAesKey(raw));
  } finally {
    raw.fill(0);
  }
}

async function refreshMe(): Promise<Me> {
  const { user } = await api.get('/me', { schema: MeResponseSchema });
  useAuth.getState().setUser(user);
  return user;
}

export function useAccountActions(): AccountActions {
  const signOut = useSignOut();
  const navigate = useNavigate();
  const mfa = useRef<{ mfaToken: string; encKey: CryptoKey } | null>(null);
  const recovery = useRef<{
    recoveryToken: string;
    wrappedAccountKeyRecovery: string;
    recoveryKey: string;
    mfaRequired: boolean;
  } | null>(null);

  return useMemo<AccountActions>(() => {
    /** After a successful credential check: start the session, then unlock the vault with the derived encKey. */
    const finishLogin = async (session: AuthSuccess, encKey: CryptoKey) => {
      useAuth.getState().setSession(session);
      try {
        const vault = await api.get('/auth/vault', { schema: VaultSchema });
        await openVault(encKey, vault.wrappedAccountKey);
      } catch {
        // The vault stays locked: the dashboard sends the user to /unlock, which asks for the password again.
      }
    };

    return {
      async register(email, password) {
        const bundle = await kdfClient.createAccountBundle(password);
        try {
          const session = await api.post(
            '/auth/register',
            {
              email,
              authKey: b64urlEncode(bundle.authKey),
              kdf: bundle.kdf,
              wrappedAccountKey: bundle.wrappedAccountKey,
              wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
              recoveryAuthHash: bundle.recoveryAuthHash,
            },
            { schema: AuthSuccessSchema, anonymous: true },
          );
          useAuth.getState().setSession(session);
          useVault.getState().setAccountKey(await importAesKey(bundle.accountKey));
          return { recoveryKey: bundle.recoveryKey };
        } finally {
          bundle.accountKey.fill(0);
        }
      },

      async login(email, password) {
        const { kdf } = await api.post(
          '/auth/prelogin',
          { email },
          {
            schema: PreloginResponseSchema,
            anonymous: true,
          },
        );
        const keys = await kdfClient.deriveAccountKeys(password, kdf);
        const res = await api.post(
          '/auth/login',
          { email, authKey: b64urlEncode(keys.authKey) },
          { schema: LoginResponseSchema, anonymous: true },
        );
        if (res.mfaRequired) {
          mfa.current = { mfaToken: res.mfaToken, encKey: keys.encKey };
          return { mfaRequired: true };
        }
        await finishLogin(res, keys.encKey);
        return { mfaRequired: false };
      },

      async completeMfa(code) {
        const pending = mfa.current;
        if (!pending)
          throw new Error('The sign-in expired. Go back and enter your password again.');
        const session = await api.post(
          '/auth/login/mfa',
          { mfaToken: pending.mfaToken, code: code.trim() },
          { schema: AuthSuccessSchema, anonymous: true },
        );
        mfa.current = null;
        await finishLogin(session, pending.encKey);
      },

      cancelMfa() {
        mfa.current = null;
      },

      async unlock(password) {
        // The vault was loaded by the page (GET /auth/vault); unwrapping is purely local.
        const vault = await queryClient.fetchQuery({
          queryKey: queryKeys.vault(),
          queryFn: () => api.get('/auth/vault', { schema: VaultSchema }),
          staleTime: 30_000,
        });
        const res = await kdfClient.unlockVault(password, vault.kdf, vault.wrappedAccountKey);
        useVault.getState().setAccountKey(res.accountKey);
      },

      async changePassword(currentPassword, newPassword) {
        const vault = await fetchVault();
        // A wrong current password fails right here, locally, before anything is sent.
        const res = await kdfClient.changePassword(
          currentPassword,
          vault.kdf,
          vault.wrappedAccountKey,
          newPassword,
        );
        await api.post(
          '/auth/password',
          {
            currentAuthKey: res.currentAuthKey,
            newAuthKey: res.newAuthKey,
            kdf: res.kdf,
            wrappedAccountKey: res.wrappedAccountKey,
          },
          { skipRefresh: true },
        );
        queryClient.removeQueries({ queryKey: queryKeys.vault() });
        void queryClient.invalidateQueries({ queryKey: queryKeys.sessions() });
        void queryClient.invalidateQueries({ queryKey: queryKeys.audit() });
      },

      async rotateRecoveryKey(password, code) {
        const vault = await fetchVault();
        const res = await kdfClient.rotateRecoveryKey(password, vault.kdf, vault.wrappedAccountKey);
        await api.post(
          '/auth/recovery/rotate',
          {
            authKey: res.authKey,
            ...(code ? { code: code.trim() } : {}),
            wrappedAccountKeyRecovery: res.wrappedAccountKeyRecovery,
            recoveryAuthHash: res.recoveryAuthHash,
          },
          { skipRefresh: true },
        );
        void queryClient.invalidateQueries({ queryKey: queryKeys.audit() });
        return { recoveryKey: res.recoveryKey };
      },

      async startRecovery(email, recoveryKey) {
        const { recoveryAuthKey } = await kdfClient.deriveRecoveryAuth(recoveryKey);
        const res = await api.post(
          '/auth/recovery/start',
          { email, recoveryAuthKey },
          { schema: RecoveryStartResponseSchema, anonymous: true },
        );
        recovery.current = {
          recoveryToken: res.recoveryToken,
          wrappedAccountKeyRecovery: res.wrappedAccountKeyRecovery,
          recoveryKey,
          mfaRequired: res.mfaRequired,
        };
        return { mfaRequired: res.mfaRequired };
      },

      async completeRecovery(newPassword, code) {
        const ctx = recovery.current;
        if (!ctx) throw new Error('The recovery session expired. Start again.');
        const res = await kdfClient.completeRecovery(
          ctx.recoveryKey,
          ctx.wrappedAccountKeyRecovery,
          newPassword,
        );
        const session = await api.post(
          '/auth/recovery/complete',
          {
            recoveryToken: ctx.recoveryToken,
            ...(code ? { code: code.trim() } : {}),
            newAuthKey: res.newAuthKey,
            kdf: res.kdf,
            wrappedAccountKey: res.wrappedAccountKey,
            wrappedAccountKeyRecovery: res.wrappedAccountKeyRecovery,
            recoveryAuthHash: res.recoveryAuthHash,
          },
          { schema: AuthSuccessSchema, anonymous: true },
        );
        recovery.current = null;
        useAuth.getState().setSession(session);
        useVault.getState().setAccountKey(res.accountKey);
        return { newRecoveryKey: res.newRecoveryKey };
      },

      async setupTotp() {
        return api.post('/auth/mfa/totp/setup', undefined, { schema: TotpSetupResponseSchema });
      },

      async enableTotp(code) {
        const res = await api.post(
          '/auth/mfa/totp/enable',
          { code: code.trim() },
          { schema: BackupCodesResponseSchema },
        );
        await refreshMe();
        void queryClient.invalidateQueries({ queryKey: queryKeys.audit() });
        return res;
      },

      async regenerateBackupCodes(code) {
        const res = await api.post(
          '/auth/mfa/backup-codes',
          { code: code.trim() },
          { schema: BackupCodesResponseSchema, skipRefresh: true },
        );
        void queryClient.invalidateQueries({ queryKey: queryKeys.audit() });
        return res;
      },

      async disableTotp(password, code) {
        const vault = await fetchVault();
        const authKey = await authKeyFor(password, vault.kdf);
        await api.post(
          '/auth/mfa/totp/disable',
          { authKey, code: code.trim() },
          { skipRefresh: true },
        );
        await refreshMe();
        void queryClient.invalidateQueries({ queryKey: queryKeys.audit() });
      },

      async deleteAccount(password, code) {
        const vault = await fetchVault();
        const authKey = await authKeyFor(password, vault.kdf);
        await api.delete(
          '/me',
          { authKey, ...(code ? { code: code.trim() } : {}) },
          { skipRefresh: true },
        );
        // Leave guarded routes first so the guards do not bounce to /login?next=.
        await navigate('/');
        await useAuth.getState().logout('account-deleted');
      },

      logout: signOut,
    };
  }, [signOut, navigate]);
}
