import { describe, expect, it } from 'vitest';
import { niceTicks } from './chartScale';
import { MAX_QUOTA_GB, parseQuotaGb, quotaToGbText } from './quota';

describe('niceTicks', () => {
  it('uses whole-number 1-2-5 steps for counts', () => {
    expect(niceTicks(9, 'count')).toEqual([0, 2, 4, 6, 8, 10]);
    expect(niceTicks(1, 'count')).toEqual([0, 1]);
    expect(niceTicks(3, 'count')).toEqual([0, 1, 2, 3]);
    expect(niceTicks(180, 'count')).toEqual([0, 50, 100, 150, 200]);
    expect(niceTicks(40, 'count')).toEqual([0, 10, 20, 30, 40]);
  });

  it('uses round steps inside the binary unit for bytes', () => {
    const MB = 1024 ** 2;
    expect(niceTicks(300 * MB, 'bytes')).toEqual([0, 100 * MB, 200 * MB, 300 * MB]);
    expect(niceTicks(1536, 'bytes')[0]).toBe(0);
  });

  it('always reaches the maximum and handles an empty series', () => {
    for (const max of [1, 7, 33, 4096, 123_456_789]) {
      const ticks = niceTicks(max, max > 5000 ? 'bytes' : 'count');
      expect(ticks[ticks.length - 1]).toBeGreaterThanOrEqual(max);
    }
    expect(niceTicks(0, 'count')).toEqual([0, 1]);
  });
});

describe('parseQuotaGb', () => {
  it('converts GB to whole bytes', () => {
    expect(parseQuotaGb('5')).toEqual({ ok: true, bytes: 5 * 1024 ** 3 });
    expect(parseQuotaGb(' 0.25 ')).toEqual({ ok: true, bytes: 1024 ** 3 / 4 });
    expect(parseQuotaGb(String(MAX_QUOTA_GB))).toMatchObject({ ok: true });
  });

  it.each(['', '  ', 'x', '-1', '1,5', '1e2', '0x10', '1.234', '0', '0.00', '10241'])(
    'rejects %j',
    (value) => {
      expect(parseQuotaGb(value).ok).toBe(false);
    },
  );

  it('round-trips through the edit field', () => {
    expect(quotaToGbText(5 * 1024 ** 3)).toBe('5');
    expect(quotaToGbText(2.5 * 1024 ** 3)).toBe('2.5');
  });
});
