// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { MAX_SAVED_NAME_CHARS, sanitizeFilename, sanitizeFilenames } from './sanitizeFilename';

const ch = (...codes: number[]) => String.fromCharCode(...codes);
const codePoints = (s: string) => Array.from(s).length;

describe('sanitizeFilename (Review Focus 1)', () => {
  it('keeps ordinary names unchanged', () => {
    expect(sanitizeFilename('holiday photo.jpg')).toBe('holiday photo.jpg');
    expect(sanitizeFilename('archive.tar.gz')).toBe('archive.tar.gz');
  });

  it('keeps emoji and RTL names intact', () => {
    const emoji = String.fromCodePoint(0x1f389, 0x1f4c4) + ' party plan.pdf';
    expect(sanitizeFilename(emoji)).toBe(emoji);
    const arabic = ch(0x062a, 0x0642, 0x0631, 0x064a, 0x0631) + '.pdf';
    expect(sanitizeFilename(arabic)).toBe(arabic);
    const hebrew = ch(0x05d3, 0x05d5, 0x05f4, 0x05d7) + ' 2026.docx';
    expect(sanitizeFilename(hebrew)).toBe(hebrew);
  });

  it('strips bidi override characters that disguise the extension', () => {
    // "invoice" + RLO + "fdp.exe" displays as "invoiceexe.pdf" but is an .exe
    const spoof = 'invoice' + ch(0x202e) + 'fdp.exe';
    expect(sanitizeFilename(spoof)).toBe('invoicefdp.exe');
    expect(sanitizeFilename('a' + ch(0x2066) + 'b' + ch(0x2069) + '.txt')).toBe('ab.txt');
  });

  it('strips path separators and traversal segments', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('etc_passwd');
    expect(sanitizeFilename('..\\..\\Windows\\System32\\drivers')).toBe('Windows_System32_drivers');
    expect(sanitizeFilename('/absolute/path.txt')).toBe('absolute_path.txt');
    expect(sanitizeFilename('..')).toBe('file');
    expect(sanitizeFilename('./')).toBe('file');
  });

  it('replaces Windows-reserved device names', () => {
    expect(sanitizeFilename('CON.txt')).toBe('_CON.txt');
    expect(sanitizeFilename('con')).toBe('_con');
    expect(sanitizeFilename('PRN')).toBe('_PRN');
    expect(sanitizeFilename('aux.log')).toBe('_aux.log');
    expect(sanitizeFilename('NUL.tar.gz')).toBe('_NUL.tar.gz');
    expect(sanitizeFilename('COM1.json')).toBe('_COM1.json');
    expect(sanitizeFilename('lpt9')).toBe('_lpt9');
    // Not reserved: longer names that merely start with a device name.
    expect(sanitizeFilename('CONSOLE.txt')).toBe('CONSOLE.txt');
    expect(sanitizeFilename('COM10.txt')).toBe('COM10.txt');
  });

  it('removes control characters and replaces characters Windows forbids', () => {
    expect(sanitizeFilename('line' + ch(0) + 'break' + ch(10, 13) + '.txt')).toBe('linebreak.txt');
    expect(sanitizeFilename('bell' + ch(7) + ch(0x7f) + ch(0x85) + '.txt')).toBe('bell.txt');
    expect(sanitizeFilename('what?<is>:this*|"q".txt')).toBe('what__is__this___q_.txt');
  });

  it('trims spaces and strips trailing dots (Windows drops them silently)', () => {
    expect(sanitizeFilename('  report.pdf  ')).toBe('report.pdf');
    expect(sanitizeFilename('notes...')).toBe('notes');
    expect(sanitizeFilename('...hidden')).toBe('hidden');
    expect(sanitizeFilename('   ')).toBe('file');
    expect(sanitizeFilename('')).toBe('file');
    expect(sanitizeFilename(ch(1, 2, 3))).toBe('file');
  });

  it('caps names at 200 characters and keeps the extension', () => {
    const long = 'a'.repeat(300) + '.pdf';
    const out = sanitizeFilename(long);
    expect(codePoints(out)).toBe(MAX_SAVED_NAME_CHARS);
    expect(out.endsWith('.pdf')).toBe(true);
    expect(out.startsWith('aaaa')).toBe(true);

    const noExt = 'b'.repeat(256);
    expect(sanitizeFilename(noExt)).toBe('b'.repeat(200));
  });

  it('never splits a surrogate pair when truncating', () => {
    const smile = String.fromCodePoint(0x1f600);
    const out = sanitizeFilename(smile.repeat(260) + '.png');
    expect(codePoints(out)).toBe(200);
    expect(out.endsWith('.png')).toBe(true);
    expect(out.slice(0, -4)).toBe(smile.repeat(196));
  });

  it('treats an over-long "extension" as part of the name', () => {
    const out = sanitizeFilename('x.' + 'y'.repeat(250));
    expect(codePoints(out)).toBe(200);
    expect(out.startsWith('x.yyy')).toBe(true);
  });

  it('a manifest name of the 1024-char maximum still becomes a valid saved name', () => {
    const name = 'n'.repeat(1020) + '.txt';
    expect(codePoints(sanitizeFilename(name))).toBeLessThanOrEqual(200);
  });
});

describe('sanitizeFilenames (duplicates within a drop)', () => {
  it('de-duplicates as name (2).ext, name (3).ext', () => {
    expect(sanitizeFilenames(['report.pdf', 'report.pdf', 'report.pdf', 'other.pdf'])).toEqual([
      'report.pdf',
      'report (2).pdf',
      'report (3).pdf',
      'other.pdf',
    ]);
  });

  it('compares case-insensitively and after sanitising', () => {
    expect(sanitizeFilenames(['Photo.JPG', 'photo.jpg', 'a/photo.jpg', 'a\\photo.jpg'])).toEqual([
      'Photo.JPG',
      'photo (2).jpg',
      'a_photo.jpg',
      'a_photo (2).jpg',
    ]);
  });

  it('skips suffixes that are already taken and handles names without extension', () => {
    expect(
      sanitizeFilenames(['notes (2).txt', 'notes.txt', 'notes.txt', 'Makefile', 'Makefile']),
    ).toEqual(['notes (2).txt', 'notes.txt', 'notes (3).txt', 'Makefile', 'Makefile (2)']);
  });

  it('keeps de-duplicated names within the 200-char cap', () => {
    const long = 'z'.repeat(400) + '.bin';
    const [a, b] = sanitizeFilenames([long, long]);
    expect(codePoints(a!)).toBe(200);
    expect(codePoints(b!)).toBe(200);
    expect(b!.endsWith(' (2).bin')).toBe(true);
    expect(a).not.toBe(b);
  });

  it('round-trips a 0-byte, emoji and reserved-name mix', () => {
    const names = ['CON.txt', 'con.txt', '', String.fromCodePoint(0x1f4a9) + '.txt'];
    expect(sanitizeFilenames(names)).toEqual([
      '_CON.txt',
      '_con (2).txt',
      'file',
      String.fromCodePoint(0x1f4a9) + '.txt',
    ]);
  });
});
