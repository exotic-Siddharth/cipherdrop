/**
 * Verification of account authKeys against the Argon2id_server PHC strings produced by lib/argon2 hashAuthKey.
 *
 * Why not lib/argon2 verifyAuthKey: @node-rs/argon2 2.2 `verify()` decodes the password as UTF-8 and throws
 * "invalid utf-8 sequence" for binary input, i.e. for almost every real 32-byte authKey (lib/argon2 then returns
 * false, so nobody could log in). `hash()`/`hashRaw()` handle raw bytes correctly (checked against hash-wasm),
 * so this module parses the PHC string and recomputes the tag with `hashRaw` on the raw bytes, then compares in
 * constant time. Hashes stay byte-for-byte compatible with hashAuthKey (seed, factories, existing rows).
 */
import { timingSafeEqual } from 'node:crypto';
import { hashRaw } from '@node-rs/argon2';
import { hashAuthKey } from '../../lib/argon2';

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

/** True iff `bytes` is the authKey behind `phc`. Never throws: malformed hashes return false. */
export async function verifyAccountAuthKey(phc: string, bytes: Uint8Array): Promise<boolean> {
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

/** Like verifyAccountAuthKey, but spends one Argon2id run when the user does not exist (no enumeration). */
export async function verifyAccountAuthKeyOrDummy(
  phc: string | null | undefined,
  bytes: Uint8Array,
): Promise<boolean> {
  if (phc) return verifyAccountAuthKey(phc, bytes);
  dummyHash ??= hashAuthKey(new Uint8Array(32));
  await verifyAccountAuthKey(await dummyHash, bytes);
  return false;
}
