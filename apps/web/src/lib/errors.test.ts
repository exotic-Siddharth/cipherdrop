import { describe, expect, it } from 'vitest';
import { describeError, isAbortError } from './errors';
import { ApiError } from './http';

describe('describeError', () => {
  it('rounds rate-limit waits UP so users never retry too early', () => {
    const limited = (retryAfter?: number) =>
      new ApiError({ status: 429, code: 'RATE_LIMITED', message: 'x', retryAfter });
    expect(describeError(limited(12))).toBe('Too many attempts. Try again in 12 s.');
    expect(describeError(limited(90))).toBe('Too many attempts. Try again in 2 min.');
    expect(describeError(limited(3601))).toBe('Too many attempts. Try again in 2 h.');
    expect(describeError(limited())).toBe('Too many attempts. Wait a moment and try again.');
  });

  it('uses server messages, hides internals and maps crypto error codes', () => {
    expect(
      describeError(new ApiError({ status: 410, code: 'GONE', message: 'This drop has expired' })),
    ).toBe('This drop has expired');
    expect(
      describeError(new ApiError({ status: 500, code: 'INTERNAL', message: 'db exploded' })),
    ).toBe('Something went wrong on our side. Please try again.');
    expect(describeError({ name: 'IntegrityError', code: 'INTEGRITY' })).toBe(
      'This file was modified in transit or storage. Download blocked.',
    );
    expect(describeError(new Error('boom'), 'Fallback.')).toBe('Fallback.');
  });

  it('recognises aborts', () => {
    const abort = new DOMException('The operation was aborted.', 'AbortError');
    expect(isAbortError(abort)).toBe(true);
    expect(describeError(abort)).toBe('Cancelled.');
  });
});
