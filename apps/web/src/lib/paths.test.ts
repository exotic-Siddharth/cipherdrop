import { describe, expect, it } from 'vitest';
import { dropPath, loginPath, reviewPath, safeNextPath, unlockPath } from './paths';

describe('safeNextPath (open-redirect guard)', () => {
  it('keeps same-origin app paths with their query and hash', () => {
    expect(safeNextPath('/dashboard')).toBe('/dashboard');
    expect(safeNextPath('/settings?tab=sessions')).toBe('/settings?tab=sessions');
    expect(safeNextPath('/d/abc#key')).toBe('/d/abc#key');
  });

  it('rejects anything that could leave the app or loop', () => {
    for (const bad of [
      null,
      undefined,
      '',
      'dashboard',
      '//evil.example',
      '/\\evil.example',
      'https://evil.example/',
      'javascript:alert(1)',
      '/%2F%2Fevil.example',
      '/login?next=/dashboard',
      '/unlock',
      '/ok\nnext',
    ]) {
      expect(safeNextPath(bad)).toBe('/dashboard');
    }
    expect(safeNextPath('//evil', '/')).toBe('/');
  });
});

describe('path builders', () => {
  it('builds app paths', () => {
    expect(dropPath('AbC_-123')).toBe('/d/AbC_-123');
    expect(reviewPath('AbC', 'k3y')).toBe('/d/AbC?review=1#k3y');
    expect(loginPath('/dashboard?x=1')).toBe('/login?next=%2Fdashboard%3Fx%3D1');
    expect(unlockPath('/dashboard')).toBe('/unlock?next=%2Fdashboard');
    expect(loginPath()).toBe('/login');
  });
});
