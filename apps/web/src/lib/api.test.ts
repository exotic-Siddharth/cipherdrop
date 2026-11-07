import type { Me } from '@cipherdrop/shared';
import { MeResponseSchema } from '@cipherdrop/shared';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuth } from '../stores/auth';
import { useVault } from '../stores/vault';
import { api, ApiError, parseRetryAfter, putBinary } from './api';

const user: Me = {
  id: 'user_1',
  email: 'ada@example.com',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 5_368_709_120,
  storageUsedBytes: 0,
  createdAt: '2026-11-07T10:00:00.000Z',
};

/** An unsigned JWT-shaped token with a 15 min lifetime (the client only reads iat/exp). */
function token(label: string): string {
  const b64 = (o: object) =>
    btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const iat = Math.floor(Date.now() / 1000);
  return `${b64({ alg: 'HS256' })}.${b64({ sub: user.id, sid: label, iat, exp: iat + 900 })}.sig`;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const unauthorized = () => json(401, { error: { code: 'UNAUTHORIZED', message: 'Unauthorized' } });
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

type FetchArgs = [input: RequestInfo | URL, init?: RequestInit];
const urlOf = (input: RequestInfo | URL) => (input instanceof Request ? input.url : String(input));
const authOf = (init?: RequestInit) => new Headers(init?.headers).get('authorization');

const OLD = token('old');
const NEW = token('new');

beforeEach(() => {
  useAuth.setState({
    status: 'authenticated',
    user,
    accessToken: OLD,
    accessTokenExpiresAt: Date.now() + 600_000,
    logoutReason: null,
  });
});

afterEach(() => {
  useAuth.setState(useAuth.getInitialState());
  useVault.setState(useVault.getInitialState());
});

describe('api client', () => {
  it('concurrent 401s trigger one refresh', async () => {
    let refreshCalls = 0;
    const fetchMock = vi.fn(async (...[input, init]: FetchArgs) => {
      const url = urlOf(input);
      if (url.endsWith('/api/auth/refresh')) {
        refreshCalls += 1;
        await delay(20);
        return json(200, { user, accessToken: NEW });
      }
      if (url.endsWith('/api/me')) {
        return authOf(init) === `Bearer ${NEW}` ? json(200, { user }) : unauthorized();
      }
      return json(404, { error: { code: 'NOT_FOUND', message: 'Not found' } });
    });
    vi.stubGlobal('fetch', fetchMock);

    const results = await Promise.all([
      api.get('/me', { schema: MeResponseSchema }),
      api.get('/me', { schema: MeResponseSchema }),
      api.get('/me', { schema: MeResponseSchema }),
    ]);

    expect(refreshCalls).toBe(1);
    expect(results).toEqual([{ user }, { user }, { user }]);
    expect(useAuth.getState().accessToken).toBe(NEW);
    expect(useAuth.getState().status).toBe('authenticated');
  });

  it('401 after failed refresh logs out with reason', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      crypto.getRandomValues(new Uint8Array(32)),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt'],
    );
    useVault.getState().setAccountKey(key);

    const fetchMock = vi.fn(async (...[input]: FetchArgs) => {
      const url = urlOf(input);
      if (url.endsWith('/api/auth/refresh')) return unauthorized();
      if (url.endsWith('/api/me')) return unauthorized();
      return json(204, null);
    });
    vi.stubGlobal('fetch', fetchMock);

    const error = await api.get('/me').catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 401, code: 'UNAUTHORIZED' });
    expect(useAuth.getState()).toMatchObject({
      status: 'anonymous',
      user: null,
      accessToken: null,
      logoutReason: 'session-expired',
    });
    // The account key never outlives the session.
    expect(useVault.getState().accountKey).toBeNull();
    // The session is already dead server-side: no logout call, and exactly one refresh attempt.
    const urls = fetchMock.mock.calls.map(([input]) => urlOf(input));
    expect(urls.filter((u) => u.endsWith('/api/auth/logout'))).toHaveLength(0);
    expect(urls.filter((u) => u.endsWith('/api/auth/refresh'))).toHaveLength(1);
  });

  it('honours Retry-After on 429 via ApiError.retryAfter (R10)', async () => {
    const fetchMock = vi.fn(async () =>
      json(
        429,
        { error: { code: 'RATE_LIMITED', message: 'Too many requests, please try again later' } },
        { 'Retry-After': '120' },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const error = await api.post('/drops/abc/unlock', { authKey: 'x' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, code: 'RATE_LIMITED', retryAfter: 120 });
    expect((error as ApiError).isRetryable).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('parses Retry-After as delta-seconds or an HTTP date', () => {
    const now = Date.UTC(2026, 10, 7, 12, 0, 0);
    expect(parseRetryAfter('30', now)).toBe(30);
    expect(parseRetryAfter(new Date(now + 90_000).toUTCString(), now)).toBe(90);
    expect(parseRetryAfter('soon', now)).toBeUndefined();
    expect(parseRetryAfter(null, now)).toBeUndefined();
  });

  it('maps the error body (code, message, details) into ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        json(410, {
          error: { code: 'GONE', message: 'This drop has expired', details: { reason: 'EXPIRED' } },
        }),
      ),
    );
    const error = await api.get('/drops/abc', { anonymous: true }).catch((e: unknown) => e);
    expect(error).toMatchObject({
      status: 410,
      code: 'GONE',
      message: 'This drop has expired',
      details: { reason: 'EXPIRED' },
    });
  });

  it('turns network failures into a retryable NETWORK_ERROR', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );
    const error = await api.get('/me').catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 0, code: 'NETWORK_ERROR' });
    expect((error as ApiError).isRetryable).toBe(true);
    // A network error is not a logout.
    expect(useAuth.getState().status).toBe('authenticated');
  });

  it('rejects responses that do not match the schema', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(200, { user: { id: 1 } })),
    );
    const error = await api.get('/me', { schema: MeResponseSchema }).catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'INVALID_RESPONSE' });
  });

  it('requests issued during boot wait for the boot refresh (one shared refresh)', async () => {
    useAuth.setState({ status: 'booting', user: null, accessToken: null });
    let refreshCalls = 0;
    const fetchMock = vi.fn(async (...[input, init]: FetchArgs) => {
      const url = urlOf(input);
      if (url.endsWith('/api/auth/refresh')) {
        refreshCalls += 1;
        await delay(20);
        return json(200, { user, accessToken: NEW });
      }
      return authOf(init) === `Bearer ${NEW}` ? json(200, { user }) : unauthorized();
    });
    vi.stubGlobal('fetch', fetchMock);

    const boot = useAuth.getState().refresh();
    const me = api.get('/me', { schema: MeResponseSchema });

    await expect(boot).resolves.toEqual({ ok: true });
    await expect(me).resolves.toEqual({ user });
    expect(refreshCalls).toBe(1);
  });

  it('serialises refreshes across tabs with navigator.locks (R22)', async () => {
    const request = vi.fn((_name: string, callback: () => Promise<unknown>) => callback());
    vi.stubGlobal('navigator', { ...navigator, locks: { request } });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(200, { user, accessToken: NEW })),
    );

    await expect(useAuth.getState().refresh()).resolves.toEqual({ ok: true });
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0]?.[0]).toBe('cd-refresh');
  });

  it('sends JSON bodies and the session bearer', async () => {
    const fetchMock = vi.fn(async () => json(200, { user }));
    vi.stubGlobal('fetch', fetchMock);
    await api.patch('/me/settings', { autoLockMinutes: 5 });
    const [input, init] = fetchMock.mock.calls[0] as unknown as FetchArgs;
    expect(urlOf(input)).toBe('/api/me/settings');
    expect(init?.method).toBe('PATCH');
    expect(init?.body).toBe(JSON.stringify({ autoLockMinutes: 5 }));
    expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
    expect(authOf(init)).toBe(`Bearer ${OLD}`);
  });

  it('never attaches the session bearer when a capability token is given', async () => {
    const fetchMock = vi.fn(async () => unauthorized());
    vi.stubGlobal('fetch', fetchMock);
    const error = await api
      .get('/drops/abc/upload-status', { token: 'upload-token' })
      .catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 401 });
    // A 401 on a capability token is final: no refresh, no logout.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(authOf((fetchMock.mock.calls[0] as unknown as FetchArgs)[1])).toBe(
      'Bearer upload-token',
    );
    expect(useAuth.getState().status).toBe('authenticated');
  });
});

describe('putBinary (worker-safe chunk upload)', () => {
  it('PUTs raw bytes with the given base URL, token and headers', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    const body = new Uint8Array([1, 2, 3]);

    await putBinary(
      '/drops/d1/files/f1/chunks/0',
      body,
      { 'x-chunk-sha256': 'ab'.repeat(32) },
      {
        baseUrl: 'http://localhost:5174',
        token: 'upload-token',
      },
    );

    const [input, init] = fetchMock.mock.calls[0] as unknown as FetchArgs;
    expect(urlOf(input)).toBe('http://localhost:5174/api/drops/d1/files/f1/chunks/0');
    expect(init?.method).toBe('PUT');
    expect(init?.body).toBe(body);
    const headers = new Headers(init?.headers);
    expect(headers.get('authorization')).toBe('Bearer upload-token');
    expect(headers.get('content-type')).toBe('application/octet-stream');
    expect(headers.get('x-chunk-sha256')).toBe('ab'.repeat(32));
  });

  it('throws ApiError with retryAfter and never refreshes', async () => {
    const fetchMock = vi.fn(async () =>
      json(429, { error: { code: 'RATE_LIMITED', message: 'Slow down' } }, { 'Retry-After': '3' }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const error = await api
      .putBinary('/drops/d1/files/f1/chunks/1', new Uint8Array([9]), {}, { token: 't' })
      .catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 429, code: 'RATE_LIMITED', retryAfter: 3 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
