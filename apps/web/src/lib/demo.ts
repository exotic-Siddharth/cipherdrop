/**
 * R24 demo account: when VITE_DEMO_CREDENTIALS ("email:password") is set at build time, the login page offers
 * "Use demo account", which fills the form. Key derivation still runs in the browser like any other login.
 * LOCAL DEV value only (apps/web/.env); the value is part of the JavaScript bundle when set.
 */
export interface DemoCredentials {
  email: string;
  password: string;
}

/** Split at the FIRST colon (passwords may contain ':'); null when unset or malformed. */
export function parseDemoCredentials(raw: string | null | undefined): DemoCredentials | null {
  const value = raw?.trim();
  if (!value) return null;
  const at = value.indexOf(':');
  if (at <= 0) return null;
  const email = value.slice(0, at).trim();
  const password = value.slice(at + 1);
  if (!password || !/^[^\s@]+@[^\s@]+$/.test(email)) return null;
  return { email, password };
}

/** The build-time demo credentials, or null (production builds normally leave them unset). */
export function getDemoCredentials(): DemoCredentials | null {
  return parseDemoCredentials(import.meta.env.VITE_DEMO_CREDENTIALS);
}
