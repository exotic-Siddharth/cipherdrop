// @vitest-environment node
/**
 * /.well-known/security.txt (RFC 9116), as apps/web/securityTxt.ts generates it for the dev and preview servers and
 * the build (deploy/nginx.conf serves the built file).
 */
import { describe, expect, it } from 'vitest';
import {
  PROJECT_SECURITY_CONTACT,
  PROJECT_SECURITY_POLICY,
  SECURITY_TXT_MAX_AGE_DAYS,
  securityTxt,
} from '../securityTxt';

const now = new Date('2026-11-20T12:34:56.789Z');

/** The fields of the file, in order, as [name, value]; comments and the final empty line left out. */
function fields(text: string): [string, string][] {
  return text
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map((line) => {
      const m = /^([A-Za-z-]+): (\S+)$/.exec(line);
      if (!m) throw new Error(`not a field line: ${line}`);
      return [m[1] as string, m[2] as string];
    });
}

describe('securityTxt', () => {
  it('points at the project by default: private vulnerability reporting and its policy', () => {
    const text = securityTxt({}, now);
    expect(fields(text)).toEqual([
      ['Contact', PROJECT_SECURITY_CONTACT],
      ['Expires', '2027-05-19T12:34:56Z'],
      ['Policy', PROJECT_SECURITY_POLICY],
      ['Preferred-Languages', 'en'],
    ]);
    expect(PROJECT_SECURITY_CONTACT).toBe(
      'https://github.com/exotic-Siddharth/cipherdrop/security/advisories/new',
    );
    expect(text.endsWith('\n')).toBe(true);
    // Blank build variables (compose passes "" when they are unset) mean the defaults too.
    expect(securityTxt({ contact: '', policy: '  ' }, now)).toBe(text);
  });

  it('expires less than a year after the build, as RFC 9116 recommends', () => {
    const expires = new Date(
      fields(securityTxt({}, now)).find(([k]) => k === 'Expires')?.[1] ?? '',
    );
    const days = (expires.getTime() - now.getTime()) / 86_400_000;
    expect(Math.round(days)).toBe(SECURITY_TXT_MAX_AGE_DAYS);
    expect(days).toBeLessThan(365);
    expect(days).toBeGreaterThanOrEqual(90);
  });

  it('tells the operator how to renew Expires: a rebuild without the build cache', () => {
    // An unchanged `up -d --build` is a cache hit for the build step and keeps the old Expires.
    const comments = securityTxt({}, now)
      .split('\n')
      .filter((line) => line.startsWith('#'));
    expect(comments.join('\n')).toMatch(/rebuild the web image without the build cache/);
    expect(comments.join('\n')).not.toMatch(/a rebuild renews/i);
  });

  it("takes the operator's contacts in order of preference, and their policy", () => {
    const text = securityTxt(
      {
        contact: 'mailto:security@drop.example, https://drop.example/report ,tel:+1-201-555-0123',
        policy: 'https://drop.example/disclosure',
      },
      now,
    );
    expect(fields(text)).toEqual([
      ['Contact', 'mailto:security@drop.example'],
      ['Contact', 'https://drop.example/report'],
      ['Contact', 'tel:+1-201-555-0123'],
      ['Expires', '2027-05-19T12:34:56Z'],
      ['Policy', 'https://drop.example/disclosure'],
      ['Preferred-Languages', 'en'],
    ]);
  });

  it.each([
    ['http://drop.example/report', 'a web contact must be https'],
    ['javascript:alert(1)', 'not a contact scheme'],
    ['mailto:', 'no address'],
    ['https://', 'no host'],
    ['security@drop.example', 'not a URI'],
    ['mailto:a@drop.example,', 'an empty entry'],
    ['mailto:a@drop.example\nPolicy: https://evil.example', 'a line break (a field of its own)'],
    ['https://drop.example/\treport', 'a tab, which the URL parser would drop'],
    ['mailto:sécurité@drop.example', 'not ASCII (use punycode)'],
  ])('refuses the contact %j (%s)', (contact) => {
    expect(() => securityTxt({ contact }, now)).toThrow(/SECURITY_TXT_CONTACT/);
  });

  it.each([
    'http://drop.example/policy',
    'mailto:security@drop.example',
    'https://x.example/\npolicy',
  ])('refuses the policy %j (https only)', (policy) => {
    expect(() => securityTxt({ policy }, now)).toThrow(/SECURITY_TXT_POLICY/);
  });
});
