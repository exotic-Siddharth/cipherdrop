/**
 * Recovery keys (spec section 7.5): RK = 20 random bytes (160 bits), shown as Crockford base32 in
 * 8 groups of 4. recoveryEnc = HKDF(RK, "cipherdrop/v1/recovery-enc"); recoveryAuth = HKDF-bits(RK,
 * "cipherdrop/v1/recovery-auth"). A fast hash is fine for the server copy because RK carries 160 bits.
 */
import {
  AAD,
  CROCKFORD_ALPHABET,
  HKDF_INFO,
  KEY_BYTES,
  RECOVERY_KEY_BYTES,
  RECOVERY_KEY_CHARS,
  RECOVERY_KEY_GROUP_SIZE,
} from './constants';
import { assertBytes, randomBytes } from './encoding';
import { hkdfKeyAndAuthBits } from './internal';
import { hashForServer } from './keys';
import { wrapKey } from './wrap';

/** Crockford decoding (after upper-casing): the 32 symbols, plus I and L read as 1 and O read as 0. */
const CROCKFORD_VALUES: ReadonlyMap<string, number> = new Map<string, number>([
  ...Array.from(CROCKFORD_ALPHABET, (c, i): [string, number] => [c, i]),
  ['I', 1],
  ['L', 1],
  ['O', 0],
]);

/** Noise in a typed or pasted key: whitespace, dashes of any kind, invisible format characters. */
const IGNORED = /[\s\p{Pd}\p{Cf}]/gu;

export interface RecoveryKey {
  raw: Uint8Array<ArrayBuffer>;
  /** XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX */
  formatted: string;
}

export interface RecoveryKeys {
  encKey: CryptoKey;
  authKey: Uint8Array<ArrayBuffer>;
}

/** Fresh recovery material for an existing AK (registration, recovery/complete and R9 rotation). */
export interface RecoveryBundle {
  /** Formatted recovery key to show once. */
  recoveryKey: string;
  /** wrap(recoveryEnc, AK, "cipherdrop/v1/wrap/recovery") */
  wrappedAccountKeyRecovery: string;
  /** b64url(SHA-256(recoveryAuth)) */
  recoveryAuthHash: string;
}

/** 20 random bytes plus their formatted Crockford form. */
export function generateRecoveryKey(): RecoveryKey {
  const raw = randomBytes(RECOVERY_KEY_BYTES);
  return { raw, formatted: formatRecoveryKey(raw) };
}

/**
 * Parse a recovery key: Crockford base32, case-insensitive, ignores '-' and spaces, I/L -> 1 and O -> 0.
 * Throws on invalid input (TypeError). Also tolerates NFKC look-alikes (full-width letters), other
 * whitespace, other dashes and zero-width characters. Error messages never contain the key.
 */
export function parseRecoveryKey(s: string): Uint8Array<ArrayBuffer> {
  if (typeof s !== 'string') throw new TypeError('A recovery key must be a string');
  const symbols = s.normalize('NFKC').replace(IGNORED, '').toUpperCase();
  if (symbols.length !== RECOVERY_KEY_CHARS) {
    throw new TypeError(
      `A recovery key has ${RECOVERY_KEY_CHARS} characters (8 groups of 4), not ${symbols.length}`,
    );
  }
  const out = new Uint8Array(RECOVERY_KEY_BYTES);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < symbols.length; i++) {
    const v = CROCKFORD_VALUES.get(symbols[i]);
    if (v === undefined) throw new TypeError(`Character ${i + 1} is not valid in a recovery key`);
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  return out;
}

/** Derive the recovery wrapping key and the recovery auth key from RK. */
export async function deriveRecoveryKeys(raw: Uint8Array): Promise<RecoveryKeys> {
  assertBytes(raw, 'The raw recovery key', RECOVERY_KEY_BYTES);
  const { key, authKey } = await hkdfKeyAndAuthBits(
    raw,
    HKDF_INFO.RECOVERY_ENC,
    HKDF_INFO.RECOVERY_AUTH,
  );
  return { encKey: key, authKey };
}

/** New recovery key for AK: generateRecoveryKey -> deriveRecoveryKeys -> wrap AK -> hashForServer. */
export async function createRecoveryBundle(accountKey: Uint8Array): Promise<RecoveryBundle> {
  assertBytes(accountKey, 'accountKey', KEY_BYTES);
  const rk = generateRecoveryKey();
  try {
    const { encKey, authKey } = await deriveRecoveryKeys(rk.raw);
    const wrappedAccountKeyRecovery = await wrapKey(encKey, accountKey, AAD.WRAP_RECOVERY);
    const recoveryAuthHash = await hashForServer(authKey);
    authKey.fill(0);
    return { recoveryKey: rk.formatted, wrappedAccountKeyRecovery, recoveryAuthHash };
  } finally {
    rk.raw.fill(0);
  }
}

/** 5-bit groups, most significant bit first: 20 bytes = 160 bits = exactly 32 symbols. */
function formatRecoveryKey(raw: Uint8Array): string {
  let symbols = '';
  let acc = 0;
  let bits = 0;
  for (const byte of raw) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      symbols += CROCKFORD_ALPHABET[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  const groups: string[] = [];
  for (let i = 0; i < symbols.length; i += RECOVERY_KEY_GROUP_SIZE) {
    groups.push(symbols.slice(i, i + RECOVERY_KEY_GROUP_SIZE));
  }
  return groups.join('-');
}
