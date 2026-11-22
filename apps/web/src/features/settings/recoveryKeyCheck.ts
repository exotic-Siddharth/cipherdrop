/**
 * "Test recovery key" (critic-5): a local check that changes nothing. The typed key is parsed, its wrapping key is
 * derived with HKDF (no Argon2id: a recovery key is 160 random bits), and an AES-GCM unwrap of the account key it
 * wraps is attempted. Success proves it is the account's current recovery key. Nothing is sent: the server only
 * hands out the wrapped account key (GET /auth/vault/recovery), and the unwrapped bytes are zeroed at once.
 */
import { AAD, deriveRecoveryKeys, parseRecoveryKey, unwrapKey } from '@cipherdrop/crypto';

export type RecoveryKeyCheck = 'valid' | 'wrong' | 'malformed';

export async function checkRecoveryKey(
  typed: string,
  wrappedAccountKeyRecovery: string,
): Promise<RecoveryKeyCheck> {
  let raw: Uint8Array;
  try {
    raw = parseRecoveryKey(typed);
  } catch {
    return 'malformed';
  }
  try {
    const { encKey, authKey } = await deriveRecoveryKeys(raw);
    authKey.fill(0);
    try {
      const accountKey = await unwrapKey(encKey, wrappedAccountKeyRecovery, AAD.WRAP_RECOVERY);
      accountKey.fill(0);
      return 'valid';
    } catch {
      return 'wrong';
    }
  } finally {
    raw.fill(0);
  }
}
