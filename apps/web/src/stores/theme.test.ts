import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import themeInitScript from '../../public/theme-init.js?raw';
import { THEME_STORAGE_KEY, useTheme } from './theme';

const html = document.documentElement;

function runThemeInit() {
  // The real file is loaded as an external <script>; executing it here proves parity with the store.
  new Function(themeInitScript)();
}

function mockSystemDark(matches: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(prefers-color-scheme: dark)' ? matches : false,
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
}

beforeEach(() => {
  localStorage.clear();
  html.classList.remove('dark');
});

afterEach(() => {
  useTheme.setState(useTheme.getInitialState());
});

describe('theme store', () => {
  it('is light-first, persists the choice and toggles the dark class', () => {
    expect(useTheme.getState().resolved).toBe('light');
    useTheme.getState().setPreference('dark');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
    expect(html.classList.contains('dark')).toBe(true);
    expect(html.style.colorScheme).toBe('dark');

    useTheme.getState().toggle();
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(html.classList.contains('dark')).toBe(false);
  });

  it('follows the system preference when set to system', () => {
    mockSystemDark(true);
    useTheme.getState().setPreference('system');
    expect(useTheme.getState().resolved).toBe('dark');
    expect(html.classList.contains('dark')).toBe(true);
  });
});

describe('public/theme-init.js (runs before React; the CSP forbids inline scripts)', () => {
  it('defaults to light and applies a saved dark theme', () => {
    runThemeInit();
    expect(html.classList.contains('dark')).toBe(false);

    localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    runThemeInit();
    expect(html.classList.contains('dark')).toBe(true);
  });

  it('resolves "system" with matchMedia and ignores garbage values', () => {
    mockSystemDark(true);
    localStorage.setItem(THEME_STORAGE_KEY, 'system');
    runThemeInit();
    expect(html.classList.contains('dark')).toBe(true);

    localStorage.setItem(THEME_STORAGE_KEY, '<script>');
    runThemeInit();
    expect(html.classList.contains('dark')).toBe(false);
  });
});
