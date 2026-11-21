import { createRecoveryBundle, generateRecoveryKey } from '@cipherdrop/crypto';
import { describe, expect, it } from 'vitest';
import { checkRecoveryKey } from './recoveryKeyCheck';

describe('checkRecoveryKey (critic-5)', () => {
  it('accepts the current key however it is typed, refuses another key and a malformed one', async () => {
    const accountKey = crypto.getRandomValues(new Uint8Array(32));
    const bundle = await createRecoveryBundle(accountKey);
    const wrapped = bundle.wrappedAccountKeyRecovery;

    expect(await checkRecoveryKey(bundle.recoveryKey, wrapped)).toBe('valid');
    const sloppy = ` ${bundle.recoveryKey.toLowerCase().replace(/-/g, ' ')} `;
    expect(await checkRecoveryKey(sloppy, wrapped)).toBe('valid');
    expect(await checkRecoveryKey(generateRecoveryKey().formatted, wrapped)).toBe('wrong');
    expect(await checkRecoveryKey('ABCD-EFGH', wrapped)).toBe('malformed');
  });
});
