import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import themeCss from '../../styles/index.css?raw';
import { Component as HowItWorksPage } from './HowItWorksPage';

type Rgb = [number, number, number];

/** The `--cd-*` colour tokens of one theme block (`:root` for light, `.dark` for dark) in styles/index.css. */
function themeTokens(theme: 'light' | 'dark'): Record<string, string> {
  const selector = theme === 'light' ? ':root' : '.dark';
  const start = themeCss.indexOf(`\n${selector} {`);
  const block = themeCss.slice(start, themeCss.indexOf('}', start));
  const tokens: Record<string, string> = {};
  for (const m of block.matchAll(/--cd-([a-z0-9-]+):\s*(#[0-9a-f]{6})/gi)) tokens[m[1]!] = m[2]!;
  return tokens;
}

function hex(value: string): Rgb {
  return [1, 3, 5].map((i) => parseInt(value.slice(i, i + 2), 16)) as Rgb;
}

/** `fg` at `alpha` over the opaque `under`, composited in sRGB like the browser does. */
function blend(fg: Rgb, under: Rgb, alpha: number): Rgb {
  return fg.map((c, i) => c * alpha + under[i]! * (1 - alpha)) as Rgb;
}

function luminance(rgb: Rgb): number {
  const [r, g, b] = rgb.map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as Rgb;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

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

  it('qualifies the never-sees claims with the opt-in abuse report key (C-39)', () => {
    renderPage();
    const table = screen.getByRole('table', { name: /what the server stores/i });
    expect(within(table).getAllByText(/abuse report/i).length).toBeGreaterThanOrEqual(2);
    expect(
      screen.getByRole('heading', { name: /abuse report can include the key/i }),
    ).toBeVisible();
    expect(screen.queryByText(/never have to fit in memory/i)).toBeNull();
  });

  it('keeps the CTA banner line at AA contrast (C-40)', () => {
    renderPage();
    expect(screen.getByText(/No account needed\. Drops up to 72 hours/)).toHaveClass(
      'text-muted-strong',
    );
  });

  it('measures the CTA banner line at >= 4.5:1 in both themes, from the theme tokens (C-40)', () => {
    renderPage();
    const known = themeTokens('light');
    const colourClass = (el: Element, prefix: 'text' | 'bg') => {
      for (const cls of el.classList) {
        const m = new RegExp(`^${prefix}-([a-z0-9-]+?)(?:/(\\d+))?$`).exec(cls);
        if (m && m[1]! in known) return { token: m[1]!, alphaPct: m[2] };
      }
      return null;
    };
    const line = screen.getByText(/No account needed\. Drops up to 72 hours/);
    const textToken = colourClass(line, 'text')!.token;
    // The nearest ancestor with a fill is the banner; it sits on the page (bg-background on <body>).
    let banner = line.parentElement;
    while (banner && !colourClass(banner, 'bg')) banner = banner.parentElement;
    const { token: fillToken, alphaPct } = colourClass(banner!, 'bg')!;
    const alpha = alphaPct ? Number(alphaPct) / 100 : 1;
    for (const theme of ['light', 'dark'] as const) {
      const tokens = themeTokens(theme);
      const bg = blend(hex(tokens[fillToken!]!), hex(tokens.background!), alpha);
      const ratio = contrast(hex(tokens[textToken]!), bg);
      expect(
        ratio,
        `${theme}: text-${textToken} on bg-${fillToken}/${alphaPct}`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('links to SECURITY.md (served by the app as plain text) and back to sending', () => {
    renderPage();
    expect(screen.getByRole('link', { name: 'docs/SECURITY.md' })).toHaveAttribute(
      'href',
      '/SECURITY.md',
    );
    expect(screen.getByRole('link', { name: 'Send files' })).toHaveAttribute('href', '/');
  });
});
