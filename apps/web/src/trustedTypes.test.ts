/**
 * Trusted Types in report-only mode (crypto-7): the header, the order index.html loads the policy in, and the rules
 * of the 'default' policy in public/trusted-types.js. The e2e suite proves the app itself trips no sink (the leak
 * guard fails on any Trusted Types console message).
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  CONTENT_SECURITY_POLICY,
  DEV_SERVER_HEADERS,
  SECURITY_HEADERS,
  TRUSTED_TYPES_REPORT_ONLY,
} from '../securityHeaders';

const read = (file: string) => readFileSync(new URL(file, import.meta.url), 'utf8');

type Rules = {
  createScriptURL: (input: string) => string | null;
  createHTML: (input: string) => string | null;
  createScript: (input: string) => string | null;
};

/** Runs public/trusted-types.js against a fake window and returns the policies it created. */
function loadPolicy(withTrustedTypes = true): Map<string, Rules> {
  const created = new Map<string, Rules>();
  const trustedTypes = withTrustedTypes
    ? {
        createPolicy: (name: string, rules: Rules) => {
          created.set(name, rules);
          return rules;
        },
      }
    : undefined;
  const fakeWindow = { trustedTypes, location: window.location };
  // Runs the shipped file as the browser would, with this fake window.
  new Function('window', 'document', read('../public/trusted-types.js'))(fakeWindow, document);
  return created;
}

describe('Trusted Types, report-only (crypto-7)', () => {
  it('ships require-trusted-types-for and the default policy as Content-Security-Policy-Report-Only', () => {
    expect(TRUSTED_TYPES_REPORT_ONLY).toBe(
      "require-trusted-types-for 'script'; trusted-types default",
    );
    expect(SECURITY_HEADERS['Content-Security-Policy-Report-Only']).toBe(TRUSTED_TYPES_REPORT_ONLY);
    // Not enforced yet: the enforced CSP has no Trusted Types directive.
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/trusted-types/);
    // The dev server sends neither policy (Vite's overlay and /src/ workers would trip it).
    expect(Object.keys(DEV_SERVER_HEADERS)).not.toContain('Content-Security-Policy-Report-Only');
    expect(Object.keys(DEV_SERVER_HEADERS)).not.toContain('Content-Security-Policy');
  });

  it('index.html loads the policy before any other script', () => {
    const scripts = [...read('../index.html').matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(
      (m) => m[1],
    );
    expect(scripts[0]).toBe('/trusted-types.js');
    expect(scripts).toContain('/src/main.tsx');
  });

  it("the 'default' policy lets through only the bundled same-origin /assets/*.js scripts", () => {
    const policy = loadPolicy().get('default')!;
    const origin = window.location.origin;
    for (const ok of [
      '/assets/upload.worker-Gcf789_u.js',
      `${origin}/assets/kdf.worker-DnmvwvEm.js`,
    ]) {
      expect(policy.createScriptURL(ok), ok).toBe(ok);
    }
    for (const bad of [
      'https://cdn.example.test/assets/x.js',
      'blob:http://localhost/7d4f1a52-2c0e-4c51-9a3b-0f1e2d3c4b5a',
      'data:text/javascript,alert(1)',
      '/src/workers/kdf.worker.ts?worker_file&type=module',
      '/assets/x.js?v=1',
      '/assets/x.js#y',
      '/assets/../api/x.js',
      '/assets/sub/x.js',
      '/x.js',
      'javascript:alert(1)',
    ]) {
      expect(policy.createScriptURL(bad), bad).toBeNull();
    }
  });

  it('the policy accepts no HTML and no script text', () => {
    const policy = loadPolicy().get('default')!;
    expect(policy.createHTML('<b>x</b>')).toBeNull();
    expect(policy.createHTML('')).toBeNull();
    expect(policy.createScript('1')).toBeNull();
  });

  it('does nothing in a browser without Trusted Types', () => {
    expect(loadPolicy(false).size).toBe(0);
  });
});
