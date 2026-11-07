import { describe, expect, it } from 'vitest';
import { ApiError } from './http';
import { dropMetaQueryOptions, queryKeys, retryDelay, shouldRetryQuery } from './queryClient';

const err = (status: number, code: ApiError['code'] = 'INTERNAL') =>
  new ApiError({ status, code, message: 'x' });

describe('TanStack retry policy (R22)', () => {
  it('never retries a 4xx (including 429) or a schema mismatch', () => {
    expect(shouldRetryQuery(0, err(400, 'VALIDATION_ERROR'))).toBe(false);
    expect(shouldRetryQuery(0, err(401, 'UNAUTHORIZED'))).toBe(false);
    expect(shouldRetryQuery(0, err(404, 'NOT_FOUND'))).toBe(false);
    expect(shouldRetryQuery(0, err(410, 'GONE'))).toBe(false);
    expect(shouldRetryQuery(0, err(429, 'RATE_LIMITED'))).toBe(false);
    expect(shouldRetryQuery(0, err(200, 'INVALID_RESPONSE'))).toBe(false);
  });

  it('retries network errors and 5xx twice with growing delays', () => {
    expect(shouldRetryQuery(0, err(0, 'NETWORK_ERROR'))).toBe(true);
    expect(shouldRetryQuery(1, err(503))).toBe(true);
    expect(shouldRetryQuery(2, err(503))).toBe(false);
    expect(retryDelay(0)).toBeLessThan(retryDelay(1));
    expect(retryDelay(10)).toBe(8_000);
  });

  it('exposes shared query keys and the read-once DropMeta options', () => {
    expect(queryKeys.myDrops({ status: 'active', page: 1, pageSize: 20 }).slice(0, 2)).toEqual(
      queryKeys.myDrops(),
    );
    expect(dropMetaQueryOptions).toMatchObject({
      staleTime: Infinity,
      refetchOnWindowFocus: false,
    });
  });
});
