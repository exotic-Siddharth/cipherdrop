import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { hashAuthKey } from '../../lib/argon2';
import { createArgon2Limiter } from '../../lib/argon2Limiter';
import {
  hashAccountAuthKey,
  verifyAccountAuthKey as verifyWith,
  verifyAccountAuthKeyOrDummy as verifyOrDummyWith,
} from './authKeyHash';

const ctx = { argon2: createArgon2Limiter({ maxConcurrent: 2, maxQueue: 32 }) };
const verifyAccountAuthKey = (phc: string, key: Uint8Array) => verifyWith(ctx, phc, key);
const verifyAccountAuthKeyOrDummy = (phc: string | null | undefined, key: Uint8Array) =>
  verifyOrDummyWith(ctx, phc, key);

describe('account authKey verification (works around @node-rs/argon2 verify() on binary input)', () => {
  it('verifies random (non-UTF-8) 32-byte keys hashed by lib/argon2 hashAuthKey', async () => {
    for (let i = 0; i < 3; i++) {
      const key = randomBytes(32);
      key[0] = 0xff; // never valid UTF-8
      const phc = await hashAuthKey(key);
      expect(await verifyAccountAuthKey(phc, key)).toBe(true);
      const other = Buffer.from(key);
      other[31] ^= 0x01;
      expect(await verifyAccountAuthKey(phc, other)).toBe(false);
    }
  });

  it('returns false (never throws) for malformed or non-argon2id hashes', async () => {
    const key = randomBytes(32);
    const phc = await hashAuthKey(key);
    const bad = [
      '',
      'not-a-hash',
      phc.replace('$argon2id$', '$argon2i$'),
      phc.replace('v=19', 'v=16'),
      phc.replace('m=19456', 'm=abc'),
      phc.slice(0, -4),
      `${phc}$extra`,
      phc.replace(/\$[^$]+\$([^$]+)$/, '$!!!!$$1'),
    ];
    for (const h of bad) expect(await verifyAccountAuthKey(h, key), h).toBe(false);
  });

  it('refuses absurd cost parameters instead of running them', async () => {
    const key = randomBytes(32);
    const phc = (await hashAuthKey(key)).replace('m=19456', 'm=4000000');
    expect(await verifyAccountAuthKey(phc, key)).toBe(false);
  });

  it('OrDummy: false for a missing hash, same answer as verify otherwise', async () => {
    const key = randomBytes(32);
    const phc = await hashAuthKey(key);
    expect(await verifyAccountAuthKeyOrDummy(null, key)).toBe(false);
    expect(await verifyAccountAuthKeyOrDummy(undefined, key)).toBe(false);
    expect(await verifyAccountAuthKeyOrDummy(phc, key)).toBe(true);
  });
});

describe('account authKey hashing goes through the Argon2 limiter (critic-1)', () => {
  it('runs every hash and verification in a slot of ctx.argon2', async () => {
    const one = { argon2: createArgon2Limiter({ maxConcurrent: 1, maxQueue: 0 }) };
    let release!: () => void;
    const held = one.argon2.run(() => new Promise<void>((resolve) => (release = resolve)));
    const key = randomBytes(32);
    const phc = await hashAuthKey(key);
    for (const call of [
      () => hashAccountAuthKey(one, key),
      () => verifyWith(one, phc, key),
      () => verifyOrDummyWith(one, null, key),
    ]) {
      await expect(call()).rejects.toMatchObject({ status: 429, code: 'RATE_LIMITED' });
    }
    release();
    await held;
    expect(await verifyWith(one, phc, key)).toBe(true);
    expect(await verifyOrDummyWith(one, phc, key)).toBe(true);
  });

  it('no module outside this one imports lib/argon2 (request paths stay bounded)', () => {
    const modules = path.resolve(import.meta.dirname, '..');
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const file = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(file);
        else if (/\.ts$/.test(entry.name) && !/\.test\.ts$/.test(entry.name)) {
          if (/from '[./]+\/lib\/argon2'/.test(readFileSync(file, 'utf8'))) {
            offenders.push(path.relative(modules, file));
          }
        }
      }
    };
    walk(modules);
    expect(offenders).toEqual([path.join('auth', 'authKeyHash.ts')]);
  });
});
