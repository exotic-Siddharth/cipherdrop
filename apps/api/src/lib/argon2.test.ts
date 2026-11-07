import { describe, expect, it } from 'vitest';
import { hashAuthKey, verifyAuthKey, verifyAuthKeyOrDummy } from './argon2';

const key = Uint8Array.from({ length: 32 }, (_, i) => i);
const other = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);

describe('R3 server-side Argon2id', () => {
  it('hashAuthKey produces an Argon2id PHC string with m=19456,t=2,p=1', async () => {
    const phc = await hashAuthKey(key);
    expect(phc).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await verifyAuthKey(phc, key)).toBe(true);
    expect(await verifyAuthKey(phc, other)).toBe(false);
  });

  it('verifyAuthKey never throws on malformed hashes; the dummy path always fails', async () => {
    expect(await verifyAuthKey('not-a-phc-string', key)).toBe(false);
    expect(await verifyAuthKeyOrDummy(null, key)).toBe(false);
  });
});
