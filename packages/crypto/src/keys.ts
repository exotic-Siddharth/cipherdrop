/**
 * Drop keys, per-file and manifest keys, hashing (spec sections 7.2 and 7.4).
 * HKDF is WebCrypto HKDF-SHA-256 with the IKM imported as a raw `HKDF` key; the salt is empty unless stated.
 */
import { AUTH_KEY_BITS, FILE_ID_BYTES, HKDF_INFO, KEY_BYTES } from './constants';
import { assertBytes, b64urlDecode, b64urlEncode, bs, randomBytes } from './encoding';
import { hkdfAesKey, subtle } from './internal';

const EMPTY_SALT = new Uint8Array(0);

/** DK: 32 random bytes per drop. It is the link secret. */
export function generateDropKey(): Uint8Array<ArrayBuffer> {
  return randomBytes(KEY_BYTES);
}

/** fileId = b64url(16 random bytes), unique within the drop. */
export function generateFileId(): string {
  return b64urlEncode(randomBytes(FILE_ID_BYTES));
}

/** fileKey = HKDF(ikm = DK, salt = b64urlDecode(fileId), info = "cipherdrop/v1/file-key") -> non-extractable AES-256-GCM key. */
export async function deriveFileKey(dk: Uint8Array, fileId: string): Promise<CryptoKey> {
  assertBytes(dk, 'dk', KEY_BYTES);
  return hkdfAesKey(dk, decodeFileId(fileId), HKDF_INFO.FILE_KEY);
}

/** manifestKey = HKDF(ikm = DK, salt = empty, info = "cipherdrop/v1/manifest-key"). */
export async function deriveManifestKey(dk: Uint8Array): Promise<CryptoKey> {
  assertBytes(dk, 'dk', KEY_BYTES);
  return hkdfAesKey(dk, EMPTY_SALT, HKDF_INFO.MANIFEST_KEY);
}

/** Import 32 raw bytes as a non-extractable AES-256-GCM key (encrypt/decrypt), e.g. the account key AK. */
export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  // Exactly 32 bytes: WebCrypto would otherwise silently accept a 16- or 24-byte AES-128/192 key.
  assertBytes(raw, 'AES key', KEY_BYTES);
  return subtle().importKey('raw', bs(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** SHA-256 digest. */
export async function sha256(b: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().digest('SHA-256', bs(b)));
}

/** b64url(SHA-256(authKey)): what the server stores and compares in constant time. */
export async function hashForServer(authKey: Uint8Array): Promise<string> {
  assertBytes(authKey, 'authKey', AUTH_KEY_BITS / 8);
  return b64urlEncode(await sha256(authKey));
}

/** The HKDF salt of a file key: fileId must be the canonical b64url of exactly 16 bytes. */
function decodeFileId(fileId: string): Uint8Array<ArrayBuffer> {
  let salt: Uint8Array<ArrayBuffer> | undefined;
  try {
    salt = b64urlDecode(fileId);
  } catch {
    // Reported below with the length check.
  }
  if (salt?.length !== FILE_ID_BYTES) {
    throw new TypeError(`fileId must be the base64url of ${FILE_ID_BYTES} bytes`);
  }
  return salt;
}
