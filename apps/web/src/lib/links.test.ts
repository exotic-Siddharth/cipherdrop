import { generateDropKey } from '@cipherdrop/crypto';
import { describe, expect, it } from 'vitest';
import { appOrigin, readShareKey, shareLinkFor } from './links';

const DROP_ID = 'AbCdEfGhIjKlMnOpQrStUw';

describe('share links (thin wrappers over @cipherdrop/crypto)', () => {
  it('builds origin/d/<id>#<43-char key> and reads the key back, even when mangled by chat apps', () => {
    const dk = generateDropKey();
    const link = shareLinkFor(DROP_ID, dk);
    expect(link.startsWith(`${appOrigin()}/d/${DROP_ID}#`)).toBe(true);
    const fragment = link.slice(link.indexOf('#'));
    expect(fragment).toHaveLength(44);

    expect(readShareKey(fragment)).toEqual(dk);
    expect(readShareKey(`${fragment}).`)).toEqual(dk);
    // location.hash keeps a literal '#'; some apps percent-encode the characters after it.
    const percentEncoded = Array.from(fragment.slice(1), (c) => `%${c.charCodeAt(0).toString(16)}`);
    expect(readShareKey(`#${percentEncoded.join('')}`)).toEqual(dk);
  });

  it('password drops have no fragment; incomplete keys read as null', () => {
    expect(shareLinkFor(DROP_ID, null)).toBe(`${appOrigin()}/d/${DROP_ID}`);
    expect(readShareKey('')).toBeNull();
    expect(readShareKey('#tooShort')).toBeNull();
  });
});
