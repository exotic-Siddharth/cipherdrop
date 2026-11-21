/**
 * /.well-known/security.txt (RFC 9116): where to report a vulnerability in this deployment. Generated rather than
 * committed, because RFC 9116 requires an Expires field: each build writes one SECURITY_TXT_MAX_AGE_DAYS ahead (the
 * RFC recommends less than a year), so an instance that has not been rebuilt for that long says its contact data may
 * be stale, and a rebuild also brings in the security fixes made since. vite.config.ts serves it from the dev and
 * preview servers and writes it into the build output, where deploy/nginx.conf serves it as UTF-8 plain text.
 *
 * Operators name their own contact when they build the web image (docs/DEPLOYMENT.md, .env.production.example):
 *   SECURITY_TXT_CONTACT  one or more mailto:, tel: or https:// URIs, comma-separated, in order of preference
 *   SECURITY_TXT_POLICY   the https:// URL of the instance's disclosure policy
 * Unset (or empty), they point at the CipherDrop project itself: GitHub private vulnerability reporting and the
 * policy in .github/SECURITY.md, which is right for the project's own instance and for reports about the code.
 */
export const PROJECT_SECURITY_CONTACT =
  'https://github.com/exotic-Siddharth/cipherdrop/security/advisories/new';
export const PROJECT_SECURITY_POLICY =
  'https://github.com/exotic-Siddharth/cipherdrop/security/policy';
export const SECURITY_TXT_MAX_AGE_DAYS = 180;
export const SECURITY_TXT_PATH = '/.well-known/security.txt';

export interface SecurityTxtConfig {
  /** SECURITY_TXT_CONTACT: comma-separated URIs. */
  contact?: string;
  /** SECURITY_TXT_POLICY: one https:// URL. */
  policy?: string;
}

/**
 * Printable ASCII without spaces only: the value is written into a line-based file, and the WHATWG URL parser
 * silently drops tabs and newlines, so a value with a line break could pass the URL check and add fields of its own.
 * An internationalised address can be given in its punycode form.
 */
const PRINTABLE = /^[\x21-\x7e]+$/;

const CONTACT_SCHEMES = ['mailto:', 'tel:', 'https:'];

/** `value` if it is a URI of one of `schemes` (an https URI with a host, a mailto: or tel: with a target). */
function checkedUri(value: string, name: string, schemes: readonly string[]): string {
  const url = PRINTABLE.test(value) && URL.canParse(value) ? new URL(value) : undefined;
  // RFC 9116: a web URI MUST be https.
  const ok =
    url !== undefined &&
    schemes.includes(url.protocol) &&
    (url.protocol === 'https:' ? url.hostname !== '' : url.pathname !== '');
  if (!ok) {
    throw new Error(`${name}: "${value}" is not one of ${schemes.join(' ')} with a target`);
  }
  return value;
}

/** The value of an optional build variable: undefined when unset or blank. */
const given = (value: string | undefined): string | undefined =>
  value === undefined || value.trim() === '' ? undefined : value.trim();

/** The file's text (LF line endings, UTF-8), valid for SECURITY_TXT_MAX_AGE_DAYS from `now`. */
export function securityTxt(config: SecurityTxtConfig = {}, now: Date = new Date()): string {
  const contactList = given(config.contact);
  const contacts =
    contactList === undefined
      ? [PROJECT_SECURITY_CONTACT]
      : contactList.split(',').map((entry) => entry.trim());
  if (contacts.some((c) => c === '')) {
    throw new Error(`SECURITY_TXT_CONTACT: an empty entry in "${contactList}"`);
  }
  for (const c of contacts) checkedUri(c, 'SECURITY_TXT_CONTACT', CONTACT_SCHEMES);
  const policy = checkedUri(
    given(config.policy) ?? PROJECT_SECURITY_POLICY,
    'SECURITY_TXT_POLICY',
    ['https:'],
  );
  const expires = new Date(now.getTime() + SECURITY_TXT_MAX_AGE_DAYS * 86_400_000);
  return [
    '# Where to report a security vulnerability in this CipherDrop instance (RFC 9116).',
    '# Generated when the web app is built; a rebuild renews Expires.',
    ...contacts.map((c) => `Contact: ${c}`),
    `Expires: ${expires.toISOString().replace(/\.\d{3}Z$/, 'Z')}`,
    `Policy: ${policy}`,
    'Preferred-Languages: en',
    '',
  ].join('\n');
}
