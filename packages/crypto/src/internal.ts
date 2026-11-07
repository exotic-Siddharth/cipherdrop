/**
 * Internal building blocks shared by the modules of @cipherdrop/crypto. NOT re-exported from index.ts.
 *
 * Helpers here take `Uint8Array<ArrayBuffer>` arguments, so every public function has to hand them a
 * private copy made with `bs()` (R19) or a buffer it created itself.
 */
import {
  AUTH_KEY_BITS,
  SALT_BYTES,
  type Argon2Params,
  type HkdfInfoLabel,
  type KdfParams,
} from './constants';
import { b64urlDecode, b64urlEncode, bs, randomBytes, utf8Encode } from './encoding';
import { KdfParamsError } from './errors';
import { argon2id, assertKdfParams } from './kdf';

const EMPTY = new Uint8Array(0);
const AES_256_GCM = { name: 'AES-GCM', length: 256 } as const;

/** WebCrypto: browsers (secure contexts only), Web Workers and Node 22, all as globalThis.crypto.subtle. */
export function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new Error(
      'WebCrypto (crypto.subtle) is unavailable: CipherDrop needs a secure context (HTTPS or localhost)',
    );
  }
  return s;
}

function hkdfParams(salt: Uint8Array, info: HkdfInfoLabel): HkdfParams {
  return { name: 'HKDF', hash: 'SHA-256', salt: bs(salt), info: utf8Encode(info) };
}

async function hkdfBaseKey(ikm: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey('raw', bs(ikm), 'HKDF', false, ['deriveKey', 'deriveBits']);
}

/** HKDF-SHA-256(ikm, salt, info) -> a non-extractable AES-256-GCM key (encrypt and decrypt). */
export async function hkdfAesKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: HkdfInfoLabel,
): Promise<CryptoKey> {
  const base = await hkdfBaseKey(ikm);
  return subtle().deriveKey(hkdfParams(salt, info), base, AES_256_GCM, false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * HKDF-SHA-256 with an empty salt, twice from one IKM: a non-extractable AES-256-GCM key under
 * `keyInfo` and 256 bits under `authInfo` (the auth key the server sees, hashed).
 */
export async function hkdfKeyAndAuthBits(
  ikm: Uint8Array,
  keyInfo: HkdfInfoLabel,
  authInfo: HkdfInfoLabel,
): Promise<{ key: CryptoKey; authKey: Uint8Array<ArrayBuffer> }> {
  const base = await hkdfBaseKey(ikm);
  const [key, bits] = await Promise.all([
    subtle().deriveKey(hkdfParams(EMPTY, keyInfo), base, AES_256_GCM, false, [
      'encrypt',
      'decrypt',
    ]),
    subtle().deriveBits(hkdfParams(EMPTY, authInfo), base, AUTH_KEY_BITS),
  ]);
  return { key, authKey: new Uint8Array(bits) };
}

/** AES-256-GCM encrypt with a 128-bit tag: returns ciphertext || tag. */
export async function gcmEncrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const params: AesGcmParams = { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 };
  return new Uint8Array(await subtle().encrypt(params, key, plaintext));
}

/** AES-256-GCM decrypt of ciphertext || tag. Rejects with WebCrypto's error; see isAuthFailure. */
export async function gcmDecrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
  sealed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const params: AesGcmParams = { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 };
  return new Uint8Array(await subtle().decrypt(params, key, sealed));
}

/**
 * True when WebCrypto reports that authenticated decryption failed (an OperationError), as opposed to
 * misuse such as a wrong key type or usage (TypeError, InvalidAccessError), which must not be reported
 * as tampering.
 */
export function isAuthFailure(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { name?: unknown }).name === 'OperationError';
}

/** True for a CryptoKey that can AES-GCM `usage` (checked structurally, so it works across realms). */
export function isAesGcmKey(key: unknown, usage: KeyUsage): key is CryptoKey {
  const k = key as Partial<CryptoKey> | null;
  return (
    typeof k === 'object' &&
    k !== null &&
    k.type === 'secret' &&
    k.algorithm?.name === 'AES-GCM' &&
    Array.isArray(k.usages) &&
    k.usages.includes(usage)
  );
}

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** New KdfParams: a fresh random 16-byte salt plus ONLY the three cost fields of `params` (checked). */
export function newKdfParams(params: Argon2Params): KdfParams {
  assertKdfParams(params);
  return {
    salt: b64urlEncode(randomBytes(SALT_BYTES)),
    memoryKiB: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
  };
}

/** Check server-provided kdf params and decode the salt, which must be the canonical b64url of 16 bytes. */
export function decodeKdfSalt(kdf: KdfParams): Uint8Array<ArrayBuffer> {
  assertKdfParams(kdf);
  let salt: Uint8Array<ArrayBuffer> | undefined;
  try {
    salt = b64urlDecode(kdf.salt);
  } catch {
    // Reported below with the length check.
  }
  if (salt?.length !== SALT_BYTES) {
    throw new KdfParamsError(`The KDF salt must be the base64url of ${SALT_BYTES} bytes`);
  }
  return salt;
}

/**
 * pk = Argon2id(NFKC(password), kdf.salt, kdf); then an AES key (keyInfo) and an auth key (authInfo)
 * via HKDF with an empty salt. The Argon2id output is zeroed afterwards (best effort in JavaScript).
 */
export async function passwordKeys(
  password: string,
  kdf: KdfParams,
  keyInfo: HkdfInfoLabel,
  authInfo: HkdfInfoLabel,
): Promise<{ key: CryptoKey; authKey: Uint8Array<ArrayBuffer> }> {
  const salt = decodeKdfSalt(kdf);
  const master = await argon2id(password, salt, kdf);
  try {
    return await hkdfKeyAndAuthBits(master, keyInfo, authInfo);
  } finally {
    master.fill(0);
  }
}
