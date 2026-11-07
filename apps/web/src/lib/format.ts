/**
 * Display formatting: sizes, durations, relative times (plan S5 interface: formatBytes, formatDuration,
 * formatRelative). Pure functions; safe in workers.
 */
import { format as formatDateFns, formatDistanceStrict } from 'date-fns';

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const;

/** 1024-based sizes with at most one decimal: "0 B", "1.5 KB", "100 MB" (104 857 600 bytes). */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${Math.round(value)} B`;
  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  // 1023.95 KB rounds to 1024: show it as the next unit instead.
  if (rounded >= 1024 && unit < BYTE_UNITS.length - 1) return `1 ${BYTE_UNITS[unit + 1]}`;
  return `${Number.isInteger(rounded) ? rounded : rounded.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

/** Transfer rate, e.g. "12.3 MB/s". */
export function formatThroughput(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

const DURATION_UNITS: ReadonlyArray<readonly [label: string, seconds: number]> = [
  ['d', 86_400],
  ['h', 3_600],
  ['min', 60],
  ['s', 1],
];

/**
 * Compact duration with the most significant units: "42 s", "2 min 5 s", "1 h 2 min", "3 d".
 * Used for ETAs and "expires in" countdowns.
 */
export function formatDuration(ms: number, options: { units?: 1 | 2 } = {}): string {
  const maxUnits = options.units ?? 2;
  if (!Number.isFinite(ms) || ms <= 0) return '0 s';
  let remaining = Math.round(ms / 1000);
  const parts: string[] = [];
  for (const [label, size] of DURATION_UNITS) {
    const count = Math.floor(remaining / size);
    remaining -= count * size;
    if (parts.length === 0) {
      if (count > 0) parts.push(`${count} ${label}`);
    } else {
      // Only the unit right after the first may follow, and only when non-zero (no "1 d 5 s").
      if (count > 0 && parts.length < maxUnits) parts.push(`${count} ${label}`);
      break;
    }
  }
  return parts.join(' ') || '0 s';
}

type DateInput = Date | string | number;

function toDate(value: DateInput): Date {
  return value instanceof Date ? value : new Date(value);
}

/** "just now", "in a few seconds", "5 minutes ago", "in 3 hours". */
export function formatRelative(value: DateInput, now: DateInput = Date.now()): string {
  const date = toDate(value);
  const base = toDate(now);
  const diff = date.getTime() - base.getTime();
  if (Number.isNaN(diff)) return '';
  if (Math.abs(diff) < 45_000) return diff < 0 ? 'just now' : 'in a few seconds';
  return formatDistanceStrict(date, base, { addSuffix: true, roundingMethod: 'round' });
}

/** Absolute local date and time: "7 Nov 2026, 14:05". */
export function formatDate(value: DateInput): string {
  const date = toDate(value);
  return Number.isNaN(date.getTime()) ? '' : formatDateFns(date, 'd MMM yyyy, HH:mm');
}

/** 0.4242 -> "42%" (clamped to 0-100%). */
export function formatPercent(ratio: number, decimals = 0): string {
  const clamped = Math.min(1, Math.max(0, Number.isFinite(ratio) ? ratio : 0));
  return `${(clamped * 100).toFixed(decimals)}%`;
}

/** pluralize(3, 'file') -> "3 files"; pluralize(2, 'entry', 'entries') -> "2 entries". */
export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}
