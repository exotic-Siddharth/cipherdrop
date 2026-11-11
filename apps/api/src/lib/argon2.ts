/**
 * Server-side Argon2id for account auth keys (spec section 7.5, R3): defence in depth on top of the
 * client-side Argon2id. Parameters equal the @node-rs/argon2 defaults (Argon2id, m=19456 KiB, t=2, p=1,
 * 32-byte output); `algorithm` is deliberately NOT passed (a const enum that breaks under isolatedModules).
 * The result is a PHC string.
 */
import { timingSafeEqual } from 'node:crypto';
import { hash, hashRaw } from '@node-rs/argon2';

const SERVER_ARGON2 = { memoryCost: 19456, timeCost: 2, parallelism: 1, outputLen: 32 } as const;

/** Argon2id_server(authKey) as a PHC string. `bytes` is the b64url-decoded 32-byte authKey. */
export async function hashAuthKey(bytes: Uint8Array): Promise<string> {
  return hash(Buffer.from(bytes), SERVER_ARGON2);
}

const PHC_RE =
  /^\$argon2id\$v=19\$m=(\d{1,7}),t=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]{11,64})\$([A-Za-z0-9+/]{22,128})$/;

/** Upper bounds well above the server parameters (m=19456, t=2, p=1): never run an absurd stored cost. */
const MAX_MEMORY_KIB = 262_144;
const MAX_TIME_COST = 10;
const MAX_PARALLELISM = 8;

interface ParsedPhc {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  salt: Buffer;
  tag: Buffer;
}

function parsePhc(phc: string): ParsedPhc | null {
  const m = typeof phc === 'string' ? PHC_RE.exec(phc) : null;
  if (!m) return null;
  const memoryCost = Number(m[1]);
  const timeCost = Number(m[2]);
  const parallelism = Number(m[3]);
  if (memoryCost < 8 || memoryCost > MAX_MEMORY_KIB) return null;
  if (timeCost < 1 || timeCost > MAX_TIME_COST) return null;
  if (parallelism < 1 || parallelism > MAX_PARALLELISM) return null;
  const salt = Buffer.from(m[4] as string, 'base64');
  const tag = Buffer.from(m[5] as string, 'base64');
  if (salt.length < 8 || tag.length < 16) return null;
  return { memoryCost, timeCost, parallelism, salt, tag };
}

/**
 * Verify a presented authKey against a stored PHC string. Never throws: malformed hashes return false.
 *
 * Not `@node-rs/argon2` verify(): it decodes the password as UTF-8 and throws for binary input, i.e. for almost
 * every real 32-byte authKey. This parses the PHC string, recomputes the tag with `hashRaw` on the raw bytes
 * and compares in constant time. Hashes stay byte-for-byte compatible with hashAuthKey.
 */
export async function verifyAuthKey(phc: string, bytes: Uint8Array): Promise<boolean> {
  const parsed = parsePhc(phc);
  if (!parsed) return false;
  try {
    const computed = await hashRaw(Buffer.from(bytes), {
      memoryCost: parsed.memoryCost,
      timeCost: parsed.timeCost,
      parallelism: parsed.parallelism,
      outputLen: parsed.tag.length,
      salt: parsed.salt,
    });
    return computed.length === parsed.tag.length && timingSafeEqual(computed, parsed.tag);
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
