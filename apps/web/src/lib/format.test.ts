import { describe, expect, it } from 'vitest';
import {
  formatBytes,
  formatDate,
  formatDuration,
  formatPercent,
  formatRelative,
  formatThroughput,
  pluralize,
} from './format';

describe('formatBytes', () => {
  it('uses 1024-based units with at most one decimal', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1)).toBe('1 B');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(4 * 1024 * 1024)).toBe('4 MB');
    expect(formatBytes(104_857_600)).toBe('100 MB');
    expect(formatBytes(12.34 * 1024 * 1024)).toBe('12.3 MB');
    expect(formatBytes(2 * 1024 ** 3)).toBe('2 GB');
    expect(formatBytes(5 * 1024 ** 4)).toBe('5 TB');
  });

  it('never prints NaN or negative sizes', () => {
    expect(formatBytes(Number.NaN)).toBe('0 B');
    expect(formatBytes(-5)).toBe('0 B');
  });
});

describe('formatDuration', () => {
  it('prints the two most significant units', () => {
    expect(formatDuration(0)).toBe('0 s');
    expect(formatDuration(999)).toBe('1 s');
    expect(formatDuration(42_000)).toBe('42 s');
    expect(formatDuration(125_000)).toBe('2 min 5 s');
    expect(formatDuration(3_725_000)).toBe('1 h 2 min');
    expect(formatDuration(90_000_000)).toBe('1 d 1 h');
    expect(formatDuration(3 * 86_400_000)).toBe('3 d');
  });

  it('can print a single unit', () => {
    expect(formatDuration(3_725_000, { units: 1 })).toBe('1 h');
    expect(formatDuration(125_000, { units: 1 })).toBe('2 min');
  });

  it('clamps invalid input', () => {
    expect(formatDuration(-1)).toBe('0 s');
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe('0 s');
  });
});

describe('formatRelative', () => {
  const now = Date.UTC(2026, 10, 7, 12, 0, 0);
  it('describes past and future times', () => {
    expect(formatRelative(now - 10_000, now)).toBe('just now');
    expect(formatRelative(now + 10_000, now)).toBe('in a few seconds');
    expect(formatRelative(now - 5 * 60_000, now)).toBe('5 minutes ago');
    expect(formatRelative(now + 3 * 3_600_000, now)).toBe('in 3 hours');
    expect(formatRelative(new Date(now - 2 * 86_400_000).toISOString(), now)).toBe('2 days ago');
  });
});

describe('small formatters', () => {
  it('formats dates, throughput, percentages and plurals', () => {
    expect(formatDate(new Date(2026, 10, 7, 14, 5))).toBe('7 Nov 2026, 14:05');
    expect(formatThroughput(12.34 * 1024 * 1024)).toBe('12.3 MB/s');
    expect(formatPercent(0.4242)).toBe('42%');
    expect(formatPercent(1.2)).toBe('100%');
    expect(pluralize(1, 'file')).toBe('1 file');
    expect(pluralize(3, 'file')).toBe('3 files');
    expect(pluralize(2, 'entry', 'entries')).toBe('2 entries');
  });
});
