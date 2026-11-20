import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { Footer } from './Footer';

function renderFooter() {
  render(
    <MemoryRouter>
      <Footer />
    </MemoryRouter>,
  );
  return screen.getByRole('navigation', { name: 'Footer' });
}

describe('Footer', () => {
  it('links to the Swagger UI of the development API', () => {
    vi.stubEnv('DEV', true);
    const nav = renderFooter();
    expect(screen.getByRole('link', { name: 'API docs' })).toHaveAttribute('href', '/api/docs');
    expect(nav).toContainElement(screen.getByRole('link', { name: 'How it works' }));
  });

  it('a production build has no link to /api/docs (Swagger UI is not served there)', () => {
    vi.stubEnv('DEV', false);
    const nav = renderFooter();
    expect(screen.queryByRole('link', { name: 'API docs' })).toBeNull();
    expect(nav.querySelector('a[href^="/api/docs"]')).toBeNull();
    expect(screen.getByRole('link', { name: 'How it works' })).toBeVisible();
  });
});
