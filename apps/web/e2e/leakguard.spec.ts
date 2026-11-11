/** The leak guard is only worth something if it can fail: prove it catches each kind of leak. */
import { expect, test } from '@playwright/test';
import { LeakGuard, textVariants } from './support/fixtures';

function guardWith(body: string | Buffer, url = 'http://localhost:5184/api/drops'): LeakGuard {
  const guard = new LeakGuard();
  guard.requests.push({
    method: 'POST',
    url,
    headers: '{"content-type":"application/json"}',
    body: Buffer.from(body),
  });
  return guard;
}

test.describe('leak guard', () => {
  test('finds a plaintext name in a JSON body', () => {
    const guard = guardWith(JSON.stringify({ name: 'tax-return-2025.pdf' }));
    guard.forbidText('file name', 'tax-return-2025.pdf');
    expect(guard.findLeaks()).toHaveLength(1);
  });

  test('finds a URL-encoded name in a query string and a base64 name in a body', () => {
    const name = 'héllo wörld.txt';
    const inUrl = guardWith('{}', `http://localhost:5184/api/x?q=${encodeURIComponent(name)}`);
    inUrl.forbidText('file name', name);
    expect(inUrl.findLeaks()).toHaveLength(1);
    const inBody = guardWith(Buffer.from(name, 'utf8').toString('base64'));
    inBody.forbidText('file name', name);
    expect(inBody.findLeaks()).toHaveLength(1);
  });

  test('finds plaintext bytes inside a binary body and the key in a header', () => {
    const plain = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef', 'utf8');
    const guard = guardWith(Buffer.concat([Buffer.from([1, 2, 3]), plain, Buffer.from([4])]));
    guard.forbidBytes('plaintext bytes', plain);
    expect(guard.findLeaks()).toHaveLength(1);
    const keyGuard = new LeakGuard();
    keyGuard.requests.push({
      method: 'GET',
      url: 'http://x/api/y',
      headers: '{"x-k":"KEY123"}',
      body: null,
    });
    keyGuard.forbidText('key', 'KEY123');
    expect(keyGuard.findLeaks()).toHaveLength(1);
  });

  test('stays quiet for unrelated bodies', () => {
    const guard = guardWith('{"encryptedManifest":"AAAA"}');
    guard.forbidText('file name', 'tax-return-2025.pdf');
    expect(guard.findLeaks()).toEqual([]);
    expect(textVariants('a b').length).toBeGreaterThan(1);
  });
});
