/**
 * Worker-backed key derivation for the browser.
 *
 * Owned by lane W1. This file starts as a scaffold stub that freezes the interface, so lanes W1, W2a and
 * W2b can work in parallel: W1 replaces the bodies (the Argon2id work runs in workers/kdf.worker.ts so the
 * UI thread never blocks) and may add methods, but must keep these exported names and signatures.
 * W2a uses deriveDropPasswordKeys and createPasswordProtection; W2 unit tests may mock this module (plan R1).
 */
import type {
  AccountBundle,
  AccountKeys,
  Argon2Params,
  DropPasswordKeys,
  KdfParams,
  PasswordProtection,
} from '@cipherdrop/crypto';

export interface KdfClient {
  /** Re-derive authKey and encKey from the password and the server-provided KDF params (login, unlock). */
  deriveAccountKeys(password: string, kdf: KdfParams): Promise<AccountKeys>;
  /** New account material for registration; params default to KDF_DEFAULT. */
  createAccountBundle(password: string, params?: Argon2Params): Promise<AccountBundle>;
  /** Derive the drop-password wrap key and authKey (receive page password prompt). */
  deriveDropPasswordKeys(password: string, kdf: KdfParams): Promise<DropPasswordKeys>;
  /** Protect a drop key with a password (send page); params default to KDF_DEFAULT. */
  createPasswordProtection(
    dk: Uint8Array,
    password: string,
    params?: Argon2Params,
  ): Promise<PasswordProtection>;
}

function notImplemented(name: string): never {
  throw new Error(`not implemented: kdfClient.${name}`);
}

export const kdfClient: KdfClient = {
  deriveAccountKeys: async () => notImplemented('deriveAccountKeys'),
  createAccountBundle: async () => notImplemented('createAccountBundle'),
  deriveDropPasswordKeys: async () => notImplemented('deriveDropPasswordKeys'),
  createPasswordProtection: async () => notImplemented('createPasswordProtection'),
};
