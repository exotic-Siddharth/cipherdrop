/**
 * Server-side Argon2id for account auth keys (spec section 7.5, R3): defence in depth on top of the
 * client-side Argon2id. Parameters equal the @node-rs/argon2 defaults (Argon2id, m=19456 KiB, t=2, p=1,
 * 32-byte output); `algorithm` is deliberately NOT passed (a const enum that breaks under isolatedModules).
 * The result is a PHC string.
 */
import { hash, verify } from '@node-rs/argon2';

const SERVER_ARGON2 = { memoryCost: 19456, timeCost: 2, parallelism: 1, outputLen: 32 } as const;

/** Argon2id_server(authKey) as a PHC string. `bytes` is the b64url-decoded 32-byte authKey. */
export async function hashAuthKey(bytes: Uint8Array): Promise<string> {
  return hash(Buffer.from(bytes), SERVER_ARGON2);
}

/** Verify a presented authKey against a stored PHC string. Never throws: malformed hashes return false. */
export async function verifyAuthKey(phc: string, bytes: Uint8Array): Promise<boolean> {
  try {
    return await verify(phc, Buffer.from(bytes));
  } catch {
    return false;
  }
}

let dummyHash: Promise<string> | undefined;

/**
 * Like verifyAuthKey, but when the user does not exist (`phc` null) it still spends one Argon2id
 * verification against a dummy hash, so response timing does not reveal whether the email exists.
 */
export async function verifyAuthKeyOrDummy(
  phc: string | null | undefined,
  bytes: Uint8Array,
): Promise<boolean> {
  if (phc) return verifyAuthKey(phc, bytes);
  dummyHash ??= hashAuthKey(new Uint8Array(32));
  await verifyAuthKey(await dummyHash, bytes);
  return false;
}
