/**
 * Key wrapping and password-protected drops (spec sections 7.4 and 7.5).
 *
 * wrap(k, bytes, aad) = b64url(nonce(12 random) || AES-GCM(k, nonce, aad, bytes))
 *
 * Only 32-byte keys are wrapped, so a wrapped key is always 60 bytes = 80 b64url chars (what the server
 * accepts), and only under the four AAD.WRAP_* labels, which keep the four uses domain-separated.
 */
import {
  AAD,
  HKDF_INFO,
  KDF_DEFAULT,
  KEY_BYTES,
  NONCE_BYTES,
  WRAPPED_KEY_BYTES,
  type Argon2Params,
  type KdfParams,
} from './constants';
import { assertBytes, b64urlDecode, b64urlEncode, bs, randomBytes, utf8Encode } from './encoding';
import { IntegrityError, WrongPasswordError } from './errors';
import {
  concatBytes,
  gcmDecrypt,
  gcmEncrypt,
  isAuthFailure,
  newKdfParams,
  passwordKeys,
} from './internal';
import { hashForServer } from './keys';

const WRAP_LABELS: ReadonlySet<string> = new Set([
  AAD.WRAP_DROP_PASSWORD,
  AAD.WRAP_ACCOUNT,
  AAD.WRAP_RECOVERY,
  AAD.WRAP_OWNER,
]);

/** Labels whose wrapping key comes from a password or a recovery key: a failed unwrap means a wrong secret. */
const WRONG_SECRET_MESSAGES: ReadonlyMap<string, string> = new Map([
  [AAD.WRAP_DROP_PASSWORD, 'Wrong password'],
  [AAD.WRAP_ACCOUNT, 'Wrong password'],
  [AAD.WRAP_RECOVERY, 'Wrong recovery key'],
]);

export interface DropPasswordKeys {
  /** HKDF(pk, info = "cipherdrop/v1/drop-password-wrap"): wraps/unwraps DK. */
  wrapKey: CryptoKey;
  /** HKDF-bits(pk, info = "cipherdrop/v1/drop-password-auth", 256): presented to POST /drops/:id/unlock and /open. */
  authKey: Uint8Array<ArrayBuffer>;
}

export interface PasswordProtection {
  kdf: KdfParams;
  wrappedDropKey: string;
  /** b64url(SHA-256(authKey)), stored by the server. */
  authKeyHash: string;
  authKey: Uint8Array<ArrayBuffer>;
}

/** Wrap raw key bytes under an AES-GCM key with the given AAD label (one of AAD.WRAP_*). */
export async function wrapKey(k: CryptoKey, bytes: Uint8Array, aad: string): Promise<string> {
  assertWrapLabel(aad);
  assertBytes(bytes, 'The key to wrap', KEY_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const sealed = await gcmEncrypt(k, nonce, utf8Encode(aad), bs(bytes));
  return b64urlEncode(concatBytes(nonce, sealed));
}

/**
 * Unwrap a blob produced by wrapKey. Throws WrongPasswordError (or IntegrityError) on failure:
 * - a malformed blob (not base64url, or not exactly 60 bytes) is an IntegrityError;
 * - an authentication failure under a password or recovery label (drop-password, account, recovery)
 *   is a WrongPasswordError, because a wrong secret is by far the likeliest cause;
 * - an authentication failure under the owner label is an IntegrityError: AK is a random key, so the
 *   blob was modified or belongs to another account.
 */
export async function unwrapKey(
  k: CryptoKey,
  blob: string,
  aad: string,
): Promise<Uint8Array<ArrayBuffer>> {
  assertWrapLabel(aad);
  if (typeof blob !== 'string') throw new TypeError('The wrapped key must be a string');
  let raw: Uint8Array<ArrayBuffer>;
  try {
    raw = b64urlDecode(blob);
  } catch (e) {
    throw new IntegrityError('The wrapped key is not valid base64url', { cause: e });
  }
  if (raw.length !== WRAPPED_KEY_BYTES) {
    throw new IntegrityError(`A wrapped key is ${WRAPPED_KEY_BYTES} bytes (got ${raw.length})`);
  }
  try {
    return await gcmDecrypt(
      k,
      raw.subarray(0, NONCE_BYTES),
      utf8Encode(aad),
      raw.subarray(NONCE_BYTES),
    );
  } catch (e) {
    if (!isAuthFailure(e)) throw e;
    const wrongSecret = WRONG_SECRET_MESSAGES.get(aad);
    if (wrongSecret) throw new WrongPasswordError(wrongSecret, { cause: e });
    throw new IntegrityError('The wrapped key failed authentication', { cause: e });
  }
}

/** pk = Argon2id(password, kdf.salt, kdf params); then wrapKey/authKey via HKDF. Validates kdf with assertKdfParams. */
export async function deriveDropPasswordKeys(
  password: string,
  kdf: KdfParams,
): Promise<DropPasswordKeys> {
  const { key, authKey } = await passwordKeys(
    password,
    kdf,
    HKDF_INFO.DROP_PASSWORD_WRAP,
    HKDF_INFO.DROP_PASSWORD_AUTH,
  );
  return { wrapKey: key, authKey };
}

/**
 * Protect DK with a password: fresh 16-byte salt, Argon2id at `params` (default KDF_DEFAULT), then
 * wrappedDropKey = wrap(wrapKey, DK, "cipherdrop/v1/wrap/drop-password").
 */
export async function createPasswordProtection(
  dk: Uint8Array,
  password: string,
  params: Argon2Params = KDF_DEFAULT,
): Promise<PasswordProtection> {
  assertBytes(dk, 'dk', KEY_BYTES);
  const kdf = newKdfParams(params);
  const keys = await deriveDropPasswordKeys(password, kdf);
  const wrappedDropKey = await wrapKey(keys.wrapKey, dk, AAD.WRAP_DROP_PASSWORD);
  const authKeyHash = await hashForServer(keys.authKey);
  return { kdf, wrappedDropKey, authKeyHash, authKey: keys.authKey };
}

function assertWrapLabel(aad: string): void {
  if (!WRAP_LABELS.has(aad)) throw new TypeError('aad must be one of the AAD.WRAP_* labels');
}
