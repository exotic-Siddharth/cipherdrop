/**
 * Password-based key derivation: Argon2id via hash-wasm (spec sections 7.4 and 7.5).
 * Passwords are normalised with `.normalize('NFKC')` before derivation.
 *
 * Parameters are checked against [KDF_MIN, KDF_MAX] before any work is done. A malicious or breached
 * server can therefore neither downgrade the cost (KDF_MIN) nor make a client exhaust its memory or
 * time (KDF_MAX).
 */
import { argon2id as hashWasmArgon2id } from 'hash-wasm';
import { DERIVED_KEY_BYTES, KDF_MAX, KDF_MIN, type Argon2Params } from './constants';
import { assertBytes, bs, utf8Encode } from './encoding';
import { KdfParamsError } from './errors';

/** Argon2 requires salts of at least 8 bytes (RFC 9106 section 3.1). CipherDrop's own salts are 16. */
const MIN_SALT_BYTES = 8;

/**
 * Argon2id(NFKC(password), salt, params) -> 32 bytes. Calls assertKdfParams first.
 * Throws TypeError for an empty password: hash-wasm cannot hash one, and CipherDrop never needs one.
 */
export async function argon2id(
  password: string,
  salt: Uint8Array,
  params: Argon2Params,
): Promise<Uint8Array<ArrayBuffer>> {
  assertKdfParams(params);
  assertBytes(salt, 'salt');
  if (salt.length < MIN_SALT_BYTES) {
    throw new KdfParamsError(`The salt must be at least ${MIN_SALT_BYTES} bytes`);
  }
  if (typeof password !== 'string') throw new TypeError('password must be a string');
  const pw = utf8Encode(password.normalize('NFKC'));
  try {
    if (pw.length === 0) throw new TypeError('password must not be empty');
    const out = await hashWasmArgon2id({
      password: pw,
      salt: bs(salt),
      iterations: params.iterations,
      parallelism: params.parallelism,
      memorySize: params.memoryKiB,
      hashLength: DERIVED_KEY_BYTES,
      outputType: 'binary',
    });
    const key = bs(out);
    out.fill(0);
    return key;
  } finally {
    pw.fill(0);
  }
}

/** Throws KdfParamsError unless KDF_MIN <= params <= KDF_MAX (downgrade and DoS protection). */
export function assertKdfParams(params: Argon2Params): void {
  if (typeof params !== 'object' || params === null) {
    throw new KdfParamsError('Key-derivation parameters must be an object');
  }
  checkRange('memoryKiB', params.memoryKiB, KDF_MIN.memoryKiB, KDF_MAX.memoryKiB);
  checkRange('iterations', params.iterations, KDF_MIN.iterations, KDF_MAX.iterations);
  checkRange('parallelism', params.parallelism, KDF_MIN.parallelism, KDF_MAX.parallelism);
}

function checkRange(name: keyof Argon2Params, value: unknown, min: number, max: number): void {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new KdfParamsError(`${name} must be an integer`);
  }
  if (value < min) {
    throw new KdfParamsError(
      `${name} = ${value} is below the minimum ${min}: weaker parameters are refused`,
    );
  }
  if (value > max) throw new KdfParamsError(`${name} = ${value} is above the maximum ${max}`);
}
