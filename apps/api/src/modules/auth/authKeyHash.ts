/**
 * Names used by the auth module for authKey verification. The implementation lives in lib/argon2 (it was first
 * written here by B1 and moved there by I1, so the seed, smoke script and every other consumer share it):
 * verification recomputes the Argon2id tag with `hashRaw` on the raw bytes, because @node-rs/argon2 `verify()`
 * rejects binary (non-UTF-8) passwords.
 */
export {
  verifyAuthKey as verifyAccountAuthKey,
  verifyAuthKeyOrDummy as verifyAccountAuthKeyOrDummy,
} from '../../lib/argon2';
