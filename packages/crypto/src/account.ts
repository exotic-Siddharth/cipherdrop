/**
 * Zero-knowledge accounts (spec section 7.5).
 *
 * mk = Argon2id(password, kdf.salt, kdf params); authKey = HKDF-bits(mk, "cipherdrop/v1/account-auth");
 * encKey = HKDF(mk, "cipherdrop/v1/account-enc"); wrappedAccountKey = wrap(encKey, AK, "cipherdrop/v1/wrap/account").
 *
 * The account key AK never changes: a password change re-wraps it, so no drop is re-encrypted.
 */
import {
  AAD,
  HKDF_INFO,
  KDF_DEFAULT,
  KEY_BYTES,
  type Argon2Params,
  type KdfParams,
} from './constants';
import { assertBytes, randomBytes } from './encoding';
import { newKdfParams, passwordKeys } from './internal';
import { createRecoveryBundle } from './recovery';
import { wrapKey } from './wrap';

export interface AccountKeys {
  /** Sent to the server as b64url; the server stores Argon2id_server(authKey). */
  authKey: Uint8Array<ArrayBuffer>;
  /** Wraps/unwraps the account key AK. */
  encKey: CryptoKey;
}

export interface AccountBundle {
  kdf: KdfParams;
  authKey: Uint8Array<ArrayBuffer>;
  /** AK: 32 random bytes. Import it as a non-extractable key for the vault (R7); never persist it. */
  accountKey: Uint8Array<ArrayBuffer>;
  wrappedAccountKey: string;
  /** Formatted recovery key (Crockford base32, 8 groups of 4). Shown once to the user. */
  recoveryKey: string;
  wrappedAccountKeyRecovery: string;
  /** b64url(SHA-256(recoveryAuth)). */
  recoveryAuthHash: string;
}

export interface RewrappedAccount {
  kdf: KdfParams;
  authKey: Uint8Array<ArrayBuffer>;
  wrappedAccountKey: string;
}

/** Re-derive authKey and encKey from the password and server-provided kdf (validated with assertKdfParams). */
export async function deriveAccountKeys(password: string, kdf: KdfParams): Promise<AccountKeys> {
  const { key, authKey } = await passwordKeys(
    password,
    kdf,
    HKDF_INFO.ACCOUNT_ENC,
    HKDF_INFO.ACCOUNT_AUTH,
  );
  return { authKey, encKey: key };
}

/** Registration: new AK, new salt (Argon2id at `params`, default KDF_DEFAULT), new recovery key. */
export async function createAccountBundle(
  password: string,
  params: Argon2Params = KDF_DEFAULT,
): Promise<AccountBundle> {
  const kdf = newKdfParams(params);
  const { authKey, encKey } = await deriveAccountKeys(password, kdf);
  const accountKey = randomBytes(KEY_BYTES);
  const wrappedAccountKey = await wrapKey(encKey, accountKey, AAD.WRAP_ACCOUNT);
  const recovery = await createRecoveryBundle(accountKey);
  return {
    kdf,
    authKey,
    accountKey,
    wrappedAccountKey,
    recoveryKey: recovery.recoveryKey,
    wrappedAccountKeyRecovery: recovery.wrappedAccountKeyRecovery,
    recoveryAuthHash: recovery.recoveryAuthHash,
  };
}

/** Password change: new salt, re-wrap the SAME AK under the new encKey. No drop is re-encrypted. */
export async function rewrapForNewPassword(
  accountKey: Uint8Array,
  newPassword: string,
  params: Argon2Params = KDF_DEFAULT,
): Promise<RewrappedAccount> {
  assertBytes(accountKey, 'accountKey', KEY_BYTES);
  const kdf = newKdfParams(params);
  const { authKey, encKey } = await deriveAccountKeys(newPassword, kdf);
  const wrappedAccountKey = await wrapKey(encKey, accountKey, AAD.WRAP_ACCOUNT);
  return { kdf, authKey, wrappedAccountKey };
}
