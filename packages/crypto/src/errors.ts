/**
 * Error classes thrown by @cipherdrop/crypto (spec section 7.7).
 *
 * Every class sets an explicit `name` and a stable `code`, so callers can still tell errors apart after
 * minification or after they cross a Worker boundary (structured clone drops prototypes; map by `code`).
 */

export type CryptoErrorCode = 'INTEGRITY' | 'WRONG_PASSWORD' | 'KDF_PARAMS' | 'INVALID_LINK';

/** Base class of every error thrown by @cipherdrop/crypto. */
export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CryptoError';
    this.code = code;
  }
}

/**
 * Authenticated decryption failed: the data was modified, truncated, reordered, extended, or decrypted
 * with the wrong key. A missing chunk is also an IntegrityError.
 */
export class IntegrityError extends CryptoError {
  constructor(
    message = 'Integrity check failed: the data was modified or is incomplete',
    options?: ErrorOptions,
  ) {
    super('INTEGRITY', message, options);
    this.name = 'IntegrityError';
  }
}

/** A password (or recovery key) did not unwrap the expected key. */
export class WrongPasswordError extends CryptoError {
  constructor(message = 'Wrong password', options?: ErrorOptions) {
    super('WRONG_PASSWORD', message, options);
    this.name = 'WrongPasswordError';
  }
}

/** Argon2id parameters are outside [KDF_MIN, KDF_MAX] (downgrade or DoS protection). */
export class KdfParamsError extends CryptoError {
  constructor(
    message = 'Key-derivation parameters are outside the allowed range',
    options?: ErrorOptions,
  ) {
    super('KDF_PARAMS', message, options);
    this.name = 'KdfParamsError';
  }
}

/** A share link or its key fragment is malformed or incomplete. */
export class InvalidLinkError extends CryptoError {
  constructor(message = 'This link is incomplete or invalid', options?: ErrorOptions) {
    super('INVALID_LINK', message, options);
    this.name = 'InvalidLinkError';
  }
}
