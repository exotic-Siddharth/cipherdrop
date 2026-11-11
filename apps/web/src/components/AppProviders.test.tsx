import { render } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { AppProviders } from './AppProviders';

describe('AppProviders', () => {
  afterEach(() => {
    document.getElementById('root')?.remove();
  });

  it('renders the toast region outside #root, which Dialog makes inert (C-21)', () => {
    const root = document.createElement('div');
    root.id = 'root';
    document.body.append(root);
    render(<AppProviders>content</AppProviders>, { container: root });
    const region = document.querySelector('section[aria-label^="Notifications"]');
    expect(region).not.toBeNull();
    expect(root.contains(region)).toBe(false);
    expect(region!.closest('[inert]')).toBeNull();
  });
});
