/**
 * Saved-file names (spec 11.3, Review Focus 1, R15). The manifest keeps the sender's original name for
 * display (up to 1024 UTF-16 units); this module turns it into a name that is safe to hand to the browser's
 * download machinery or showSaveFilePicker on every OS:
 *
 * - path separators split the name and traversal segments ('', '.', '..') are dropped: '../../etc/passwd'
 *   becomes 'etc_passwd';
 * - control characters (C0, DEL, C1) and invisible bidi controls (which can disguise an extension) are removed;
 * - characters Windows forbids (<>:"|?*) become '_';
 * - surrounding spaces and leading/trailing dots are stripped (Windows drops trailing ones silently);
 * - Windows device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with any extension) get a '_' prefix;
 * - names are capped at 200 code points, keeping the extension, without splitting surrogate pairs;
 * - an empty result becomes 'file';
 * - sanitizeFilenames() de-duplicates within a drop as 'name (2).ext' (case-insensitively).
 *
 * Pure and dependency-free: safe in workers and tests.
 */

export const MAX_SAVED_NAME_CHARS = 200;
/** Longest suffix (without the dot) still treated as an extension worth preserving. */
const MAX_EXTENSION_CHARS = 16;
const FALLBACK_NAME = 'file';

const RESERVED_DEVICE_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
const WINDOWS_FORBIDDEN_RE = /[<>:"|?*]/g;

function isRemovedCodePoint(cp: number): boolean {
  return (
    cp <= 0x1f || // C0 controls
    (cp >= 0x7f && cp <= 0x9f) || // DEL and C1 controls
    cp === 0x200e || // LEFT-TO-RIGHT MARK
    cp === 0x200f || // RIGHT-TO-LEFT MARK
    (cp >= 0x202a && cp <= 0x202e) || // bidi embeddings and overrides
    (cp >= 0x2066 && cp <= 0x2069) || // bidi isolates
    cp === 0xfeff // byte-order mark / zero-width no-break space
  );
}

function stripInvisible(s: string): string {
  let out = '';
  for (const c of s) {
    if (!isRemovedCodePoint(c.codePointAt(0) ?? 0)) out += c;
  }
  return out;
}

/** Split into base and extension (with its dot). The extension must be short and the base non-empty. */
function splitExtension(name: string): { base: string; ext: string } {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { base: name, ext: '' };
  const ext = name.slice(dot);
  if (Array.from(ext).length - 1 > MAX_EXTENSION_CHARS) return { base: name, ext: '' };
  return { base: name.slice(0, dot), ext };
}

/** Truncate `base` so that base + suffix + ext fits in MAX_SAVED_NAME_CHARS code points. */
function fit(base: string, suffix: string, ext: string): string {
  const room = MAX_SAVED_NAME_CHARS - Array.from(suffix).length - Array.from(ext).length;
  const points = Array.from(base);
  if (room <= 0) {
    // Extension and suffix alone exceed the cap (not reachable with MAX_EXTENSION_CHARS = 16).
    return Array.from(base + suffix + ext)
      .slice(0, MAX_SAVED_NAME_CHARS)
      .join('');
  }
  const trimmedBase = points.length > room ? points.slice(0, room).join('').trimEnd() : base;
  return `${trimmedBase}${suffix}${ext}`;
}

/** A single name, sanitised for saving (not de-duplicated). */
export function sanitizeFilename(name: string): string {
  const raw = typeof name === 'string' ? name : '';
  const segments = stripInvisible(raw)
    .split(/[/\\]+/)
    .map((s) => s.trim())
    .filter((s) => s !== '' && s !== '.' && s !== '..');
  let s = segments.join('_').replace(WINDOWS_FORBIDDEN_RE, '_');
  // Leading dots would hide the file on Unix; trailing dots and spaces vanish on Windows.
  s = s.replace(/^[.\s]+/, '').replace(/[.\s]+$/, '');
  if (s === '') return FALLBACK_NAME;

  const firstDot = s.indexOf('.');
  const device = (firstDot === -1 ? s : s.slice(0, firstDot)).trimEnd();
  if (RESERVED_DEVICE_RE.test(device)) s = `_${s}`;

  if (Array.from(s).length <= MAX_SAVED_NAME_CHARS) return s;
  const { base, ext } = splitExtension(s);
  return fit(base, '', ext);
}

/**
 * Sanitise every name of a drop and de-duplicate them in order: the first keeps its name, later collisions
 * become 'name (2).ext', 'name (3).ext', ... skipping names already taken. Comparison is case-insensitive
 * because Windows and macOS file systems are.
 */
export function sanitizeFilenames(names: readonly string[]): string[] {
  const sanitized = names.map(sanitizeFilename);
  const taken = new Set<string>();
  // Reserve every original sanitised name first, so "notes (2).txt" sent by the user stays as it is.
  const reserved = new Set(sanitized.map((n) => n.toLowerCase()));
  const out: string[] = [];
  for (const name of sanitized) {
    const key = name.toLowerCase();
    if (!taken.has(key)) {
      taken.add(key);
      out.push(name);
      continue;
    }
    const { base, ext } = splitExtension(name);
    let n = 2;
    let candidate = fit(base, ` (${n})`, ext);
    while (taken.has(candidate.toLowerCase()) || reserved.has(candidate.toLowerCase())) {
      n += 1;
      candidate = fit(base, ` (${n})`, ext);
    }
    taken.add(candidate.toLowerCase());
    out.push(candidate);
  }
  return out;
}
