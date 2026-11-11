import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { hashAuthKey } from '../../lib/argon2';
import { verifyAccountAuthKey, verifyAccountAuthKeyOrDummy } from './authKeyHash';

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
