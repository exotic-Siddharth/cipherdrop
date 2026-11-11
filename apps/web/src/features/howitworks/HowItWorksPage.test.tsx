import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { Component as HowItWorksPage } from './HowItWorksPage';

function renderPage() {
  render(
    <MemoryRouter>
      <HowItWorksPage />
    </MemoryRouter>,
  );
}

describe('HowItWorksPage', () => {
  it('has one h1 and the five numbered sections', () => {
    renderPage();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    const sections = screen.getAllByRole('region');
    expect(sections.length).toBeGreaterThanOrEqual(5);
    expect(screen.getByRole('heading', { name: /the key sits in the link/i })).toBeVisible();
    expect(screen.getByRole('heading', { name: /honest limitations/i })).toBeVisible();
  });

  it('draws three labelled inline SVG diagrams', () => {
    renderPage();
    const images = screen.getAllByRole('img');
    expect(images).toHaveLength(3);
    for (const svg of images) {
      expect(svg.tagName.toLowerCase()).toBe('svg');
      expect(svg).toHaveAccessibleName();
    }
  });

  it('has the server stores / never sees table', () => {
    renderPage();
    const table = screen.getByRole('table', { name: /what the server stores/i });
    expect(within(table).getByRole('columnheader', { name: /the server stores/i })).toBeVisible();
    expect(within(table).getByRole('columnheader', { name: /never sees/i })).toBeVisible();
    expect(within(table).getByText(/file names, file types or your note/i)).toBeVisible();
  });

  it('points to SECURITY.md and back to sending', () => {
    renderPage();
    expect(screen.getByText('docs/SECURITY.md')).toBeVisible();
    expect(screen.getByRole('link', { name: 'Send files' })).toHaveAttribute('href', '/');
  });
});
