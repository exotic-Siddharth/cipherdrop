/**
 * Key-derivation worker (spec 11.3): every Argon2id computation of the app runs here, so the UI thread never
 * freezes. The logic lives in the plain function handleKdfRequest() so tests can run it in-process (R20).
 *
 * Protocol (module worker, many requests in flight, matched by id):
 *   main -> worker  { id, request: KdfRequest }
 *   worker -> main  { id, ok: true, result } | { id, ok: false, error: {code, message} }
 *
 * Structured clone drops error classes and `.code`, so errors cross the boundary as {code, message} and
 * kdfClient maps them back to the @cipherdrop/crypto classes by code.
 *
 * Composite operations (unlockVault, changePassword, rotateRecoveryKey, completeRecovery) keep the raw account
 * key AK inside the worker: it is unwrapped, used and zeroed there. Only a NON-extractable CryptoKey (R7) or
 * already-wrapped material leaves. Only worker-safe modules are imported (@cipherdrop/*): never the stores.
 */
import {
  AAD,
  b64urlEncode,
  createAccountBundle,
  createPasswordProtection,
  createRecoveryBundle,
  CryptoError,
  deriveAccountKeys,
  deriveDropPasswordKeys,
  deriveRecoveryKeys,
  importAesKey,
  parseRecoveryKey,
  rewrapForNewPassword,
  unwrapKey,
  type AccountBundle,
  type AccountKeys,
  type Argon2Params,
  type DropPasswordKeys,
  type KdfParams,
  type PasswordProtection,
} from '@cipherdrop/crypto';

export type KdfRequest =
  | { op: 'deriveAccountKeys'; password: string; kdf: KdfParams }
  | { op: 'createAccountBundle'; password: string; params?: Argon2Params }
  | { op: 'deriveDropPasswordKeys'; password: string; kdf: KdfParams }
  | { op: 'createPasswordProtection'; dk: Uint8Array; password: string; params?: Argon2Params }
  | { op: 'unlockVault'; password: string; kdf: KdfParams; wrappedAccountKey: string }
  | {
      op: 'changePassword';
      currentPassword: string;
      kdf: KdfParams;
      wrappedAccountKey: string;
      newPassword: string;
      params?: Argon2Params;
    }
  | { op: 'rotateRecoveryKey'; password: string; kdf: KdfParams; wrappedAccountKey: string }
  | { op: 'deriveRecoveryAuth'; recoveryKey: string }
  | {
      op: 'completeRecovery';
      recoveryKey: string;
      wrappedAccountKeyRecovery: string;
      newPassword: string;
      params?: Argon2Params;
    };

/** Result of unlockVault: the proof of password (authKey, b64url) and the vault key (non-extractable). */
export interface UnlockVaultResult {
  authKey: string;
  accountKey: CryptoKey;
}

/** Body parts of POST /auth/password. */
export interface ChangePasswordResult {
  currentAuthKey: string;
  newAuthKey: string;
  kdf: KdfParams;
  wrappedAccountKey: string;
}

/** Body parts of POST /auth/recovery/rotate plus the new key to show once. */
export interface RotateRecoveryResult {
  authKey: string;
  recoveryKey: string;
  wrappedAccountKeyRecovery: string;
  recoveryAuthHash: string;
}

export interface RecoveryAuthResult {
  recoveryAuthKey: string;
}

/** Body parts of POST /auth/recovery/complete plus the vault key and the new recovery key to show once. */
export interface CompleteRecoveryResult {
  newAuthKey: string;
  kdf: KdfParams;
  wrappedAccountKey: string;
  wrappedAccountKeyRecovery: string;
  recoveryAuthHash: string;
  newRecoveryKey: string;
  accountKey: CryptoKey;
}

export interface KdfResultMap {
  deriveAccountKeys: AccountKeys;
  createAccountBundle: AccountBundle;
  deriveDropPasswordKeys: DropPasswordKeys;
  createPasswordProtection: PasswordProtection;
  unlockVault: UnlockVaultResult;
  changePassword: ChangePasswordResult;
  rotateRecoveryKey: RotateRecoveryResult;
  deriveRecoveryAuth: RecoveryAuthResult;
  completeRecovery: CompleteRecoveryResult;
}

export type KdfOp = KdfRequest['op'];
export type KdfResultOf<R extends KdfRequest> = KdfResultMap[R['op']];

export interface KdfRequestMessage {
  id: number;
  request: KdfRequest;
}

export interface SerializedKdfError {
  code: string;
  message: string;
}

export type KdfResponseMessage =
  { id: number; ok: true; result: unknown } | { id: number; ok: false; error: SerializedKdfError };

/** Error -> {code, message}: crypto errors keep their stable code, misuse is TYPE_ERROR / RANGE_ERROR. */
export function serializeKdfError(err: unknown): SerializedKdfError {
  if (err instanceof CryptoError) return { code: err.code, message: err.message };
  if (err instanceof TypeError) return { code: 'TYPE_ERROR', message: err.message };
  if (err instanceof RangeError) return { code: 'RANGE_ERROR', message: err.message };
  const code = (err as { code?: unknown } | null)?.code;
  const message = err instanceof Error ? err.message : 'Key derivation failed';
  return { code: typeof code === 'string' ? code : 'UNKNOWN', message };
}

/** Unwrap AK with `encKey` and import it as the non-extractable vault key. The raw bytes are zeroed. */
async function openVaultKey(encKey: CryptoKey, wrappedAccountKey: string): Promise<CryptoKey> {
  const raw = await unwrapKey(encKey, wrappedAccountKey, AAD.WRAP_ACCOUNT);
  try {
    return await importAesKey(raw);
  } finally {
    raw.fill(0);
  }
}

export async function handleKdfRequest<R extends KdfRequest>(req: R): Promise<KdfResultOf<R>>;
export async function handleKdfRequest(req: KdfRequest): Promise<unknown> {
  switch (req.op) {
    case 'deriveAccountKeys':
      return deriveAccountKeys(req.password, req.kdf);
    case 'createAccountBundle':
      return createAccountBundle(req.password, req.params);
    case 'deriveDropPasswordKeys':
      return deriveDropPasswordKeys(req.password, req.kdf);
    case 'createPasswordProtection':
      return createPasswordProtection(req.dk, req.password, req.params);

    case 'unlockVault': {
      const { authKey, encKey } = await deriveAccountKeys(req.password, req.kdf);
      const accountKey = await openVaultKey(encKey, req.wrappedAccountKey);
      return { authKey: b64urlEncode(authKey), accountKey } satisfies UnlockVaultResult;
    }

    case 'changePassword': {
      const current = await deriveAccountKeys(req.currentPassword, req.kdf);
      const ak = await unwrapKey(current.encKey, req.wrappedAccountKey, AAD.WRAP_ACCOUNT);
      try {
        const next = await rewrapForNewPassword(ak, req.newPassword, req.params);
        return {
          currentAuthKey: b64urlEncode(current.authKey),
          newAuthKey: b64urlEncode(next.authKey),
          kdf: next.kdf,
          wrappedAccountKey: next.wrappedAccountKey,
        } satisfies ChangePasswordResult;
      } finally {
        ak.fill(0);
      }
    }

    case 'rotateRecoveryKey': {
      const current = await deriveAccountKeys(req.password, req.kdf);
      const ak = await unwrapKey(current.encKey, req.wrappedAccountKey, AAD.WRAP_ACCOUNT);
      try {
        const bundle = await createRecoveryBundle(ak);
        return { authKey: b64urlEncode(current.authKey), ...bundle } satisfies RotateRecoveryResult;
      } finally {
        ak.fill(0);
      }
    }

    case 'deriveRecoveryAuth': {
      const raw = parseRecoveryKey(req.recoveryKey);
      try {
        const { authKey } = await deriveRecoveryKeys(raw);
        return { recoveryAuthKey: b64urlEncode(authKey) } satisfies RecoveryAuthResult;
      } finally {
        raw.fill(0);
      }
    }

    case 'completeRecovery': {
      const raw = parseRecoveryKey(req.recoveryKey);
      let ak: Uint8Array | null = null;
      try {
        const { encKey } = await deriveRecoveryKeys(raw);
        ak = await unwrapKey(encKey, req.wrappedAccountKeyRecovery, AAD.WRAP_RECOVERY);
        const next = await rewrapForNewPassword(ak, req.newPassword, req.params);
        const recovery = await createRecoveryBundle(ak);
        const accountKey = await importAesKey(ak);
        return {
          newAuthKey: b64urlEncode(next.authKey),
          kdf: next.kdf,
          wrappedAccountKey: next.wrappedAccountKey,
          wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
          recoveryAuthHash: recovery.recoveryAuthHash,
          newRecoveryKey: recovery.recoveryKey,
          accountKey,
        } satisfies CompleteRecoveryResult;
      } finally {
        raw.fill(0);
        ak?.fill(0);
      }
    }
  }
}

interface WorkerScopeLike {
  postMessage(msg: KdfResponseMessage): void;
  addEventListener(type: 'message', listener: (ev: MessageEvent<KdfRequestMessage>) => void): void;
}

const scope = globalThis as unknown as { WorkerGlobalScope?: unknown } & WorkerScopeLike;
if (typeof scope.WorkerGlobalScope !== 'undefined') {
  scope.addEventListener('message', (ev) => {
    const { id, request } = ev.data;
    handleKdfRequest(request).then(
      (result) => scope.postMessage({ id, ok: true, result }),
      (err: unknown) => scope.postMessage({ id, ok: false, error: serializeKdfError(err) }),
    );
  });
}
