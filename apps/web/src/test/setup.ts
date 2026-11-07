/**
 * Vitest setup for apps/web (jsdom by default; R20 pipeline tests opt into node).
 * Adds the jest-dom matchers, unmounts after each test, and fills the few browser APIs jsdom lacks.
 */
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});

if (typeof window !== 'undefined') {
  // jsdom has no matchMedia: report "no preference" for every query (tests can override it).
  if (typeof window.matchMedia !== 'function') {
    window.matchMedia = (query: string): MediaQueryList =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        addListener: () => undefined,
        removeListener: () => undefined,
        dispatchEvent: () => false,
      }) as MediaQueryList;
  }
  // jsdom logs "Not implemented" for these (React Router's ScrollRestoration calls scrollTo).
  window.scrollTo = () => undefined;
  if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => undefined;
}
