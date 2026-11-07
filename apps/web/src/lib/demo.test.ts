import { describe, expect, it } from 'vitest';
import { parseDemoCredentials } from './demo';

describe('parseDemoCredentials (R24)', () => {
  it('splits email:password at the first colon', () => {
    expect(parseDemoCredentials('demo@cipherdrop.local:demo-cipherdrop-dev-2026')).toEqual({
      email: 'demo@cipherdrop.local',
      password: 'demo-cipherdrop-dev-2026',
    });
    expect(parseDemoCredentials(' demo@x.test:pa:ss:word ')).toEqual({
      email: 'demo@x.test',
      password: 'pa:ss:word',
    });
  });

  it('returns null when unset or malformed', () => {
    expect(parseDemoCredentials(undefined)).toBeNull();
    expect(parseDemoCredentials('')).toBeNull();
    expect(parseDemoCredentials('no-colon')).toBeNull();
    expect(parseDemoCredentials(':password')).toBeNull();
    expect(parseDemoCredentials('demo@x.test:')).toBeNull();
    expect(parseDemoCredentials('not-an-email:password')).toBeNull();
  });
});
