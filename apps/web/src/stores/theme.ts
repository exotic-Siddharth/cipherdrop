/**
 * Theme preference (light-first, spec 11.1). Persisted in localStorage under THEME_STORAGE_KEY; it is the only
 * thing the SPA keeps in Web Storage besides the device-drops list and the upload-resume record.
 *
 * public/theme-init.js applies the saved theme before first paint (external file: the CSP forbids inline
 * scripts, R22). Keep its logic in sync with resolveTheme() below.
 */
import { create } from 'zustand';

export type ThemePreference = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'cd-theme';
/** <meta name="theme-color"> per theme (the page background tokens). */
export const THEME_COLORS: Readonly<Record<ResolvedTheme, string>> = Object.freeze({
  light: '#f6f7f9',
  dark: '#0b1014',
});

const DARK_QUERY = '(prefers-color-scheme: dark)';

function systemPrefersDark(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia(DARK_QUERY).matches
    : false;
}

export function readStoredPreference(): ThemePreference {
  try {
    const v = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (v === 'light' || v === 'dark' || v === 'system') return v;
  } catch {
    // Storage blocked (privacy mode): fall back to the default.
  }
  return 'light';
}

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  if (preference === 'system') return systemPrefersDark() ? 'dark' : 'light';
  return preference;
}

/** Apply a resolved theme to <html> (the `dark` class drives Tailwind's dark variant and the tokens). */
export function applyTheme(
  theme: ResolvedTheme,
  root: HTMLElement = document.documentElement,
): void {
  root.classList.toggle('dark', theme === 'dark');
  root.style.colorScheme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', THEME_COLORS[theme]);
}

export interface ThemeState {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
  /** Flip between light and dark (the navbar toggle). */
  toggle: () => void;
  /** Re-resolve after a system or cross-tab change. */
  sync: () => void;
}

const initialPreference: ThemePreference =
  typeof window === 'undefined' ? 'light' : readStoredPreference();

export const useTheme = create<ThemeState>()((set, get) => ({
  preference: initialPreference,
  resolved: typeof window === 'undefined' ? 'light' : resolveTheme(initialPreference),

  setPreference: (preference) => {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, preference);
    } catch {
      // Not persisted; still applied for this page.
    }
    const resolved = resolveTheme(preference);
    applyTheme(resolved);
    set({ preference, resolved });
  },

  toggle: () => get().setPreference(get().resolved === 'dark' ? 'light' : 'dark'),

  sync: () => {
    const preference = readStoredPreference();
    const resolved = resolveTheme(preference);
    applyTheme(resolved);
    set({ preference, resolved });
  },
}));

/** Follow OS changes (when the preference is 'system') and changes made in other tabs. Returns a stop function. */
export function startThemeSync(): () => void {
  const media = window.matchMedia?.(DARK_QUERY);
  const onSystem = () => {
    if (useTheme.getState().preference === 'system') useTheme.getState().sync();
  };
  const onStorage = (e: StorageEvent) => {
    if (e.key === THEME_STORAGE_KEY) useTheme.getState().sync();
  };
  media?.addEventListener?.('change', onSystem);
  window.addEventListener('storage', onStorage);
  // theme-init.js already painted the right theme; this only aligns the meta tag and the store.
  useTheme.getState().sync();
  return () => {
    media?.removeEventListener?.('change', onSystem);
    window.removeEventListener('storage', onStorage);
  };
}
