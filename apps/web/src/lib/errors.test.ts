import { describe, expect, it } from 'vitest';
import { ErrorCodeSchema } from '@cipherdrop/shared';
import { describeError, isAbortError } from './errors';
import { formatDate } from './format';
import { ApiError, errorFromResponse } from './http';

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

  it('explains the hosting-abuse controls (server-1, ops-3)', () => {
    const budget = new ApiError({
      status: 429,
      code: 'UPLOAD_BUDGET_EXCEEDED',
      message: 'x',
      details: { limitBytes: 1024 ** 3, windowHours: 24 },
      retryAfter: 5 * 3600 - 10,
    });
    expect(describeError(budget)).toBe(
      'You have sent 1 GB without an account in the last 24 hours, the limit for anonymous senders. Try again in 5 h, or sign in to send more.',
    );
    expect(
      describeError(new ApiError({ status: 429, code: 'UPLOAD_BUDGET_EXCEEDED', message: 'x' })),
    ).toBe(
      'You have sent a lot without an account recently. Try again later, or sign in to send more.',
    );

    expect(describeError(new ApiError({ status: 507, code: 'STORAGE_FULL', message: 'x' }))).toBe(
      "This server's storage is full, so it is not accepting new uploads right now. Please try again later.",
    );

    const disabled = (feature: string) =>
      new ApiError({
        status: 403,
        code: 'FEATURE_DISABLED',
        message: 'server text',
        details: { feature },
      });
    expect(describeError(disabled('anonymousUploads'))).toBe(
      'This server accepts uploads from signed-in users only. Log in to send files.',
    );
    expect(describeError(disabled('registration'))).toBe(
      'This server is not accepting new accounts right now.',
    );
    expect(describeError(disabled('something-new'))).toBe('server text');
  });

  it('names the new-account quota and its end date in QUOTA_EXCEEDED', () => {
    const ends = '2026-11-27T09:00:00.000Z';
    const probation = new ApiError({
      status: 413,
      code: 'QUOTA_EXCEEDED',
      message: 'server text',
      details: { quotaBytes: 256 * 1024 ** 2, usedBytes: 200 * 1024 ** 2, probationEndsAt: ends },
    });
    expect(describeError(probation)).toBe(
      `Your storage is full. New accounts can store up to 256 MB until ${formatDate(ends)}. Delete a drop, or wait until then.`,
    );
    const plain = new ApiError({
      status: 413,
      code: 'QUOTA_EXCEEDED',
      message: 'Storage quota exceeded',
      details: { quotaBytes: 10, usedBytes: 10 },
    });
    expect(describeError(plain)).toBe('Storage quota exceeded');
  });

  it('recognises aborts', () => {
    const abort = new DOMException('The operation was aborted.', 'AbortError');
    expect(isAbortError(abort)).toBe(true);
    expect(describeError(abort)).toBe('Cancelled.');
  });
});

describe('errorFromResponse', () => {
  it('keeps every server error code, so the SPA can tell them apart', async () => {
    for (const code of ErrorCodeSchema.options) {
      const res = new Response(JSON.stringify({ error: { code, message: 'm' } }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
      expect((await errorFromResponse(res)).code, code).toBe(code);
    }
  });
});
