import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../lib/http';
import { disabledFeature, noteDisabledFeature, useServerConfig } from './serverConfig';

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

afterEach(() => {
  useServerConfig.setState(useServerConfig.getInitialState(), true);
  vi.unstubAllGlobals();
});

describe('useServerConfig', () => {
  it('loads the switches from GET /api/config without a session', async () => {
    const fetchMock = vi.fn(async () => json(200, { anonymousUploads: false, registration: true }));
    vi.stubGlobal('fetch', fetchMock);
    await useServerConfig.getState().load();
    expect(useServerConfig.getState().config).toEqual({
      anonymousUploads: false,
      registration: true,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/config');
    expect(new Headers(init.headers).get('authorization')).toBeNull();
  });

  it('stays unknown (null) when the request fails or the answer is malformed', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(500, { error: { code: 'INTERNAL', message: 'x' } })),
    );
    await useServerConfig.getState().load();
    expect(useServerConfig.getState().config).toBeNull();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(200, { anonymousUploads: 'no' })),
    );
    await useServerConfig.getState().load();
    expect(useServerConfig.getState().config).toBeNull();
  });

  it('a 403 FEATURE_DISABLED marks that feature off and leaves the others alone', () => {
    const err = new ApiError({
      status: 403,
      code: 'FEATURE_DISABLED',
      message: 'x',
      details: { feature: 'registration' },
    });
    expect(disabledFeature(err)).toBe('registration');
    expect(noteDisabledFeature(err)).toBe(true);
    expect(useServerConfig.getState().config).toEqual({
      anonymousUploads: true,
      registration: false,
    });
    const other = new ApiError({ status: 403, code: 'FORBIDDEN', message: 'x' });
    expect(disabledFeature(other)).toBeNull();
    expect(noteDisabledFeature(other)).toBe(false);
    expect(disabledFeature(new Error('x'))).toBeNull();
  });
});
