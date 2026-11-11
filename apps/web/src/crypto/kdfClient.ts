/**
 * Worker-backed key derivation for the browser.
 *
 * All Argon2id work runs in workers/kdf.worker.ts (one lazily created module worker, requests matched by id),
 * so the UI thread never blocks. Errors cross the boundary as {code, message} and are mapped back to the
 * @cipherdrop/crypto error classes by code (structured clone drops the class and `.code`).
 *
 * The first four members are the interface frozen by the scaffold (W2a uses deriveDropPasswordKeys and
 * createPasswordProtection; its unit tests may mock this module, plan R1). The other members are the account
 * flows of W1: the raw account key AK never leaves the worker, only non-extractable keys and wrapped material do.
 */
import {
  IntegrityError,
  InvalidLinkError,
  KdfParamsError,
  WrongPasswordError,
  type AccountBundle,
  type AccountKeys,
  type Argon2Params,
  type DropPasswordKeys,
  type KdfParams,
  type PasswordProtection,
} from '@cipherdrop/crypto';
import type {
  ChangePasswordResult,
  CompleteRecoveryResult,
  KdfRequest,
  KdfRequestMessage,
  KdfResponseMessage,
  KdfResultOf,
  RecoveryAuthResult,
  RotateRecoveryResult,
  SerializedKdfError,
  UnlockVaultResult,
} from '../workers/kdf.worker';

export type {
  ChangePasswordResult,
  CompleteRecoveryResult,
  RecoveryAuthResult,
  RotateRecoveryResult,
  UnlockVaultResult,
} from '../workers/kdf.worker';

export interface KdfClient {
  /** Re-derive authKey and encKey from the password and the server-provided KDF params (login, unlock). */
  deriveAccountKeys(password: string, kdf: KdfParams): Promise<AccountKeys>;
  /** New account material for registration; params default to KDF_DEFAULT. */
  createAccountBundle(password: string, params?: Argon2Params): Promise<AccountBundle>;
  /** Derive the drop-password wrap key and authKey (receive page password prompt). */
  deriveDropPasswordKeys(password: string, kdf: KdfParams): Promise<DropPasswordKeys>;
  /** Protect a drop key with a password (send page); params default to KDF_DEFAULT. */
  createPasswordProtection(
    dk: Uint8Array,
    password: string,
    params?: Argon2Params,
  ): Promise<PasswordProtection>;
}

/** Account flows (W1). All of them derive with Argon2id in the worker. */
export interface AccountKdfOps {
  /** Derive, unwrap AK and return it as a non-extractable vault key (R7), plus the authKey (b64url). */
  unlockVault(
    password: string,
    kdf: KdfParams,
    wrappedAccountKey: string,
  ): Promise<UnlockVaultResult>;
  /** Password change: current authKey, new authKey/kdf and the SAME AK re-wrapped. Re-derives AK transiently. */
  changePassword(
    currentPassword: string,
    kdf: KdfParams,
    wrappedAccountKey: string,
    newPassword: string,
    params?: Argon2Params,
  ): Promise<ChangePasswordResult>;
  /** Recovery-key rotation (R9): authKey plus a new recovery key bundle for the same AK. */
  rotateRecoveryKey(
    password: string,
    kdf: KdfParams,
    wrappedAccountKey: string,
  ): Promise<RotateRecoveryResult>;
  /** The recoveryAuthKey (b64url) for POST /auth/recovery/start. Throws TypeError for a malformed key. */
  deriveRecoveryAuth(recoveryKey: string): Promise<RecoveryAuthResult>;
  /** Unwrap AK with the recovery key, set a new password and rotate the recovery key. */
  completeRecovery(
    recoveryKey: string,
    wrappedAccountKeyRecovery: string,
    newPassword: string,
    params?: Argon2Params,
  ): Promise<CompleteRecoveryResult>;
}

/** The minimal Worker surface kdfClient needs (a test double can implement it). */
interface WorkerLike {
  postMessage(message: KdfRequestMessage): void;
  addEventListener(type: 'message', listener: (ev: MessageEvent<KdfResponseMessage>) => void): void;
  addEventListener(type: 'error' | 'messageerror', listener: (ev: Event) => void): void;
  terminate(): void;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
}

let worker: WorkerLike | null = null;
let nextId = 1;
const pending = new Map<number, Pending>();

/** Map a {code, message} that crossed the worker boundary back to an error class. */
export function errorFromWorker(error: SerializedKdfError): Error {
  switch (error.code) {
    case 'WRONG_PASSWORD':
      return new WrongPasswordError(error.message);
    case 'KDF_PARAMS':
      return new KdfParamsError(error.message);
    case 'INTEGRITY':
      return new IntegrityError(error.message);
    case 'INVALID_LINK':
      return new InvalidLinkError(error.message);
    case 'TYPE_ERROR':
      return new TypeError(error.message);
    case 'RANGE_ERROR':
      return new RangeError(error.message);
    default:
      return Object.assign(new Error(error.message), { code: error.code });
  }
}

function failAll(reason: Error) {
  const entries = [...pending.values()];
  pending.clear();
  for (const p of entries) p.reject(reason);
}

function getWorker(): WorkerLike {
  if (worker) return worker;
  const w = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as WorkerLike;
  w.addEventListener('message', (ev) => {
    const msg = ev.data;
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    if (msg.ok) entry.resolve(msg.result);
    else entry.reject(errorFromWorker(msg.error));
  });
  const onFatal = () => {
    // The worker died (failed to load, out of memory): fail what is waiting and start fresh next time.
    if (worker === w) worker = null;
    w.terminate();
    failAll(new Error('Local key derivation failed. Reload the page and try again.'));
  };
  w.addEventListener('error', onFatal);
  w.addEventListener('messageerror', onFatal);
  worker = w;
  return w;
}

function call<R extends KdfRequest>(request: R): Promise<KdfResultOf<R>> {
  return new Promise<KdfResultOf<R>>((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
    try {
      getWorker().postMessage({ id, request });
    } catch (err) {
      pending.delete(id);
      reject(err);
    }
  });
}

/** Terminate the worker and fail pending calls (tests, and the "sign out" path). */
export function resetKdfWorker(): void {
  const w = worker;
  worker = null;
  w?.terminate();
  failAll(new Error('Key derivation was cancelled'));
}

export const kdfClient: KdfClient & AccountKdfOps = {
  deriveAccountKeys: (password, kdf) => call({ op: 'deriveAccountKeys', password, kdf }),
  createAccountBundle: (password, params) => call({ op: 'createAccountBundle', password, params }),
  deriveDropPasswordKeys: (password, kdf) => call({ op: 'deriveDropPasswordKeys', password, kdf }),
  createPasswordProtection: (dk, password, params) =>
    call({ op: 'createPasswordProtection', dk, password, params }),
  unlockVault: (password, kdf, wrappedAccountKey) =>
    call({ op: 'unlockVault', password, kdf, wrappedAccountKey }),
  changePassword: (currentPassword, kdf, wrappedAccountKey, newPassword, params) =>
    call({ op: 'changePassword', currentPassword, kdf, wrappedAccountKey, newPassword, params }),
  rotateRecoveryKey: (password, kdf, wrappedAccountKey) =>
    call({ op: 'rotateRecoveryKey', password, kdf, wrappedAccountKey }),
  deriveRecoveryAuth: (recoveryKey) => call({ op: 'deriveRecoveryAuth', recoveryKey }),
  completeRecovery: (recoveryKey, wrappedAccountKeyRecovery, newPassword, params) =>
    call({ op: 'completeRecovery', recoveryKey, wrappedAccountKeyRecovery, newPassword, params }),
};
