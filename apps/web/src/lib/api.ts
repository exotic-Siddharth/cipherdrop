/**
 * Session-aware API client (spec 11.3, plan S5 interface).
 *
 *   api.get('/me', { schema: MeResponseSchema })            -> GET /api/me, validated
 *   api.post('/drops', body, { schema: CreateDropResponseSchema })
 *   api.delete('/drops/' + id, undefined, { headers: { [OWNER_TOKEN_HEADER]: ownerToken } })
 *   api.get(chunkPath, { token: downloadToken, raw: true }) -> the Response (stream it yourself)
 *   api.putBinary(chunkPath, bytes, { [CHUNK_SHA256_HEADER]: hex }, { token: uploadToken })
 *
 * - Paths are relative to /api. The session access token is attached automatically (memory only).
 * - 401 on a session request -> ONE shared refresh (stores/auth.ts) -> one retry. If the refresh is rejected
 *   the session ends with reason 'session-expired' and the original 401 is thrown.
 * - Requests made while the session is still booting wait for the boot refresh first.
 * - `token` sends a capability token (upload/download) instead; such 401s are final (no refresh).
 * - Every failure rejects with ApiError {status, code, message, details, retryAfter?}; AbortError passes through.
 */
import type { ZodType, ZodTypeDef } from 'zod';
import { useAuth } from '../stores/auth';
import {
  ApiError,
  apiUrl,
  errorFromResponse,
  networkError,
  putBinary,
  type QueryParams,
} from './http';

export { ApiError, apiUrl, isApiError, parseRetryAfter, putBinary } from './http';
export type { ApiErrorCode, BinaryRequestContext, QueryParams, QueryValue } from './http';

export interface RequestOptions<T = unknown> {
  /** Validate (and type) the JSON response; a mismatch rejects with code INVALID_RESPONSE. */
  schema?: ZodType<T, ZodTypeDef, unknown>;
  /** Query-string parameters (undefined/null/'' are skipped). */
  query?: QueryParams;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Capability bearer (uploadToken, downloadToken) instead of the session token. Never refreshed. */
  token?: string;
  /** Send no Authorization header even when signed in (public endpoints). */
  anonymous?: boolean;
  /** Do not refresh-and-retry on 401 (and skip the proactive refresh). */
  skipRefresh?: boolean;
}

export interface RawRequestOptions extends Omit<RequestOptions, 'schema'> {
  /** Resolve with the Response itself (after the ok check): chunk downloads, blobs. */
  raw: true;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Refresh shortly before the access token expires instead of collecting a 401 first. */
const REFRESH_AHEAD_MS = 30_000;

function isBinaryBody(body: unknown): body is BodyInit {
  return (
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body) ||
    (typeof Blob !== 'undefined' && body instanceof Blob) ||
    (typeof FormData !== 'undefined' && body instanceof FormData) ||
    (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) ||
    (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream)
  );
}

async function send(
  method: HttpMethod,
  path: string,
  body: unknown,
  opts: RequestOptions<unknown>,
): Promise<Response> {
  const useSession = !opts.token && !opts.anonymous;

  if (useSession) {
    const s = useAuth.getState();
    if (s.status === 'booting') {
      await s.refresh();
    } else if (
      !opts.skipRefresh &&
      s.status === 'authenticated' &&
      s.accessTokenExpiresAt !== null &&
      s.accessTokenExpiresAt - Date.now() < REFRESH_AHEAD_MS
    ) {
      await s.refresh();
    }
  }

  const attempt = async (): Promise<{ res: Response; usedToken: string | null }> => {
    const headers = new Headers(opts.headers);
    if (!headers.has('accept')) headers.set('accept', 'application/json');
    let usedToken: string | null = null;
    if (opts.token) {
      headers.set('authorization', `Bearer ${opts.token}`);
    } else if (useSession) {
      usedToken = useAuth.getState().accessToken;
      if (usedToken) headers.set('authorization', `Bearer ${usedToken}`);
    }
    let payload: BodyInit | undefined;
    if (body !== undefined && body !== null) {
      if (isBinaryBody(body)) {
        payload = body;
      } else {
        headers.set('content-type', 'application/json');
        payload = JSON.stringify(body);
      }
    }
    try {
      const res = await fetch(apiUrl(path, { query: opts.query }), {
        method,
        headers,
        body: payload,
        credentials: 'same-origin',
        cache: 'no-store',
        signal: opts.signal,
      });
      return { res, usedToken };
    } catch (err) {
      throw networkError(err);
    }
  };

  const first = await attempt();
  const usedToken = first.usedToken;
  let res = first.res;

  if (res.status === 401 && useSession && usedToken && !opts.skipRefresh) {
    const current = useAuth.getState().accessToken;
    let retry = current !== null && current !== usedToken; // someone else already refreshed
    if (!retry) {
      const result = await useAuth.getState().refresh();
      if (result.ok) retry = true;
      else if (result.reason !== 'unauthorized') {
        throw new ApiError({
          status: 0,
          code: 'NETWORK_ERROR',
          message: "Can't reach CipherDrop to renew your session. Try again in a moment.",
        });
      }
    }
    if (retry) {
      void res.body?.cancel().catch(() => undefined);
      ({ res } = await attempt());
    }
  }

  if (!res.ok) throw await errorFromResponse(res);
  return res;
}

async function parse<T>(res: Response, schema?: ZodType<T, ZodTypeDef, unknown>): Promise<T> {
  if (res.status === 204 || res.status === 205) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (cause) {
    throw new ApiError({
      status: res.status,
      code: 'INVALID_RESPONSE',
      message: 'The server sent an unreadable response.',
      cause,
    });
  }
  if (!schema) return data as T;
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    throw new ApiError({
      status: res.status,
      code: 'INVALID_RESPONSE',
      message: 'The server sent an unexpected response.',
      details: {
        issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      },
    });
  }
  return parsed.data;
}

function request(
  method: HttpMethod,
  path: string,
  body: unknown,
  opts: RawRequestOptions,
): Promise<Response>;
function request<T = unknown>(
  method: HttpMethod,
  path: string,
  body?: unknown,
  opts?: RequestOptions<T>,
): Promise<T>;
async function request<T>(
  method: HttpMethod,
  path: string,
  body?: unknown,
  opts: RequestOptions<T> | RawRequestOptions = {},
): Promise<T | Response> {
  const res = await send(method, path, body, opts as RequestOptions<unknown>);
  if ('raw' in opts && opts.raw) return res;
  return parse(res, (opts as RequestOptions<T>).schema);
}

export interface ApiClient {
  request: typeof request;
  get(path: string, opts: RawRequestOptions): Promise<Response>;
  get<T = unknown>(path: string, opts?: RequestOptions<T>): Promise<T>;
  post(path: string, body: unknown, opts: RawRequestOptions): Promise<Response>;
  post<T = unknown>(path: string, body?: unknown, opts?: RequestOptions<T>): Promise<T>;
  put(path: string, body: unknown, opts: RawRequestOptions): Promise<Response>;
  put<T = unknown>(path: string, body?: unknown, opts?: RequestOptions<T>): Promise<T>;
  patch(path: string, body: unknown, opts: RawRequestOptions): Promise<Response>;
  patch<T = unknown>(path: string, body?: unknown, opts?: RequestOptions<T>): Promise<T>;
  delete(path: string, body: unknown, opts: RawRequestOptions): Promise<Response>;
  delete<T = unknown>(path: string, body?: unknown, opts?: RequestOptions<T>): Promise<T>;
  /** Raw chunk PUT; also importable from ./http inside Web Workers. */
  putBinary: typeof putBinary;
}

type AnyOptions = RequestOptions<unknown> | RawRequestOptions;
const call = (method: HttpMethod) => (path: string, body?: unknown, opts?: AnyOptions) =>
  request(method, path, body, opts as RequestOptions<unknown>);

export const api: ApiClient = {
  request,
  get: ((path: string, opts?: AnyOptions) =>
    request('GET', path, undefined, opts as RequestOptions<unknown>)) as ApiClient['get'],
  post: call('POST') as ApiClient['post'],
  put: call('PUT') as ApiClient['put'],
  patch: call('PATCH') as ApiClient['patch'],
  delete: call('DELETE') as ApiClient['delete'],
  putBinary,
};
