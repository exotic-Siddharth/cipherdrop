/**
 * Account authKey hashing for request handlers. The Argon2id implementation lives in lib/argon2 (it was first
 * written here by B1 and moved there by I1, so the seed, smoke script and every other consumer share it):
 * verification recomputes the Argon2id tag with `hashRaw` on the raw bytes, because @node-rs/argon2 `verify()`
 * rejects binary (non-UTF-8) passwords.
 *
 * These wrappers run each hash in the app's Argon2 limiter (ctx.argon2, lib/argon2Limiter.ts), which caps the
 * concurrent hashes and answers 429 + Retry-After when its queue is full (critic-1). Route code must use them,
 * never lib/argon2 directly (a test in authKeyHash.test.ts checks the imports).
 */
import type { AppContext } from '../../context';
import { hashAuthKey, verifyAuthKey, verifyAuthKeyOrDummy } from '../../lib/argon2';

type Ctx = Pick<AppContext, 'argon2'>;

/** Argon2id_server(authKey) as a PHC string, in a limiter slot. */
export function hashAccountAuthKey(ctx: Ctx, bytes: Uint8Array): Promise<string> {
  return ctx.argon2.run(() => hashAuthKey(bytes));
}

/** Verify a presented authKey against a stored PHC string, in a limiter slot. Never throws for bad hashes. */
export function verifyAccountAuthKey(ctx: Ctx, phc: string, bytes: Uint8Array): Promise<boolean> {
  return ctx.argon2.run(() => verifyAuthKey(phc, bytes));
}

/** Like verifyAccountAuthKey, but spends one dummy verification when the user does not exist (timing). */
export function verifyAccountAuthKeyOrDummy(
  ctx: Ctx,
  phc: string | null | undefined,
  bytes: Uint8Array,
): Promise<boolean> {
  return ctx.argon2.run(() => verifyAuthKeyOrDummy(phc, bytes));
}
