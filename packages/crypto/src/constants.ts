/**
 * CipherDrop cryptographic constants (spec section 7.1, normative).
 *
 * Changing any value here breaks compatibility with every existing drop, link and account.
 * This module is dependency-free so other packages can import it via `@cipherdrop/crypto/constants`.
 */

/** Construction version (manifest `v`, label prefix `cipherdrop/v1`). */
export const VERSION = 1 as const;

/** Plaintext bytes per chunk: 4 MiB. */
export const CHUNK_SIZE = 4 * 1024 * 1024; // 4 194 304
/** AES-GCM authentication tag length. Each ciphertext chunk = plaintext length + TAG_BYTES. */
export const TAG_BYTES = 16;
/** AES-GCM nonce length. */
export const NONCE_BYTES = 12;
/** AES-256 key length; also the drop key (DK) and account key (AK) length. */
export const KEY_BYTES = 32;
/** Random bytes in a client-generated fileId (also its HKDF salt). */
export const FILE_ID_BYTES = 16;
/** Argon2id salt length for drop passwords and accounts. */
export const SALT_BYTES = 16;
/** Argon2id output length (and HKDF-bits output for auth keys). */
export const DERIVED_KEY_BYTES = 32;
/** HKDF-bits length of every auth key sent to the server. */
export const AUTH_KEY_BITS = 256;
/** Largest ciphertext chunk: a full plaintext chunk plus its tag. */
export const MAX_CHUNK_CIPHERTEXT_BYTES = CHUNK_SIZE + TAG_BYTES;

/** Argon2id cost parameters (32-byte output). */
export interface Argon2Params {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/** Argon2id parameters as stored by the server and sent to clients: salt is b64url(16 bytes). */
export interface KdfParams extends Argon2Params {
  salt: string;
}

/** Default Argon2id parameters for new drop passwords and accounts. */
export const KDF_DEFAULT: Readonly<Argon2Params> = Object.freeze({
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
});

/** The client REFUSES weaker parameters (downgrade protection). */
export const KDF_MIN: Readonly<Argon2Params> = Object.freeze({
  memoryKiB: 19456,
  iterations: 2,
  parallelism: 1,
});

/** The client refuses absurd parameters (denial of service against the recipient). */
export const KDF_MAX: Readonly<Argon2Params> = Object.freeze({
  memoryKiB: 262144,
  iterations: 10,
  parallelism: 4,
});

/** HKDF-SHA-256 `info` labels (UTF-8). The salt is empty unless stated otherwise in spec section 7. */
export const HKDF_INFO = Object.freeze({
  FILE_KEY: 'cipherdrop/v1/file-key',
  MANIFEST_KEY: 'cipherdrop/v1/manifest-key',
  DROP_PASSWORD_WRAP: 'cipherdrop/v1/drop-password-wrap',
  DROP_PASSWORD_AUTH: 'cipherdrop/v1/drop-password-auth',
  ACCOUNT_AUTH: 'cipherdrop/v1/account-auth',
  ACCOUNT_ENC: 'cipherdrop/v1/account-enc',
  RECOVERY_ENC: 'cipherdrop/v1/recovery-enc',
  RECOVERY_AUTH: 'cipherdrop/v1/recovery-auth',
} as const);

/** AES-GCM additional authenticated data labels (UTF-8). */
export const AAD = Object.freeze({
  CHUNK: 'cipherdrop/v1/chunk',
  MANIFEST: 'cipherdrop/v1/manifest',
  WRAP_DROP_PASSWORD: 'cipherdrop/v1/wrap/drop-password',
  WRAP_ACCOUNT: 'cipherdrop/v1/wrap/account',
  WRAP_RECOVERY: 'cipherdrop/v1/wrap/recovery',
  WRAP_OWNER: 'cipherdrop/v1/wrap/owner',
} as const);

export type HkdfInfoLabel = (typeof HKDF_INFO)[keyof typeof HKDF_INFO];
export type AadLabel = (typeof AAD)[keyof typeof AAD];

/* ---- Manifest limits (spec section 7.3; R15) ---- */

export const MANIFEST_VERSION = 1 as const;
export const MAX_FILES_PER_DROP = 20;
export const MAX_NOTE_CHARS = 2000;
/** File names allow up to 1024 UTF-16 code units for display; saved names are capped at 200 (R15). */
export const MAX_FILE_NAME_CHARS = 1024;
export const MAX_FILE_TYPE_CHARS = 255;
/** encryptedManifest is at most 64 KiB once base64url-encoded. */
export const MAX_ENCRYPTED_MANIFEST_CHARS = 64 * 1024;

/* ---- Encoded lengths (base64url, no padding) ---- */

/** b64url(32 bytes): share-link fragment, auth keys, SHA-256 hashes. */
export const B64URL_32_CHARS = 43;
/** b64url(16 bytes): fileId, dropId, KDF salt. */
export const B64URL_16_CHARS = 22;
/** Share-link fragment length: b64url(DK). */
export const SHARE_KEY_CHARS = B64URL_32_CHARS;
/** fileId length: b64url(16 random bytes). */
export const FILE_ID_CHARS = B64URL_16_CHARS;
/** wrap(k, 32-byte key) = b64url(nonce(12) || ciphertext(32) || tag(16)) = 60 bytes = 80 chars. */
export const WRAPPED_KEY_BYTES = NONCE_BYTES + KEY_BYTES + TAG_BYTES;
export const WRAPPED_KEY_CHARS = 80;

/* ---- Recovery key (spec section 7.5) ---- */

/** Recovery key entropy: 20 random bytes = 160 bits. */
export const RECOVERY_KEY_BYTES = 20;
/** Crockford base32 alphabet (no I, L, O, U). */
export const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** Formatted as 8 groups of 4 Crockford characters: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX. */
export const RECOVERY_KEY_GROUPS = 8;
export const RECOVERY_KEY_GROUP_SIZE = 4;
export const RECOVERY_KEY_CHARS = RECOVERY_KEY_GROUPS * RECOVERY_KEY_GROUP_SIZE; // 32
