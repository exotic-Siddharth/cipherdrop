/**
 * Worker-safe HTTP primitives: ApiError, URL building, error parsing and raw chunk PUTs.
 *
 * This module never touches the DOM, Web Storage or the auth store, so module workers
 * (upload.worker.ts) can import it. The session-aware client lives in ./api.ts.
 */
import type { ErrorCode } from '@cipherdrop/shared';
import { API_PREFIX } from '@cipherdrop/shared';

/** Server error codes (spec section 10) plus two client-side ones. */
export type ApiErrorCode = ErrorCode | 'NETWORK_ERROR' | 'INVALID_RESPONSE';

export interface ApiErrorInit {
  status: number;
  code: ApiErrorCode;
  message: string;
  details?: unknown;
  /** Seconds to wait before retrying (parsed Retry-After header). */
  retryAfter?: number;
  cause?: unknown;
}

/** Every failed API call rejects with this. `status` is 0 for network failures. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: ApiErrorCode;
  readonly details: unknown;
  readonly retryAfter: number | undefined;

  constructor(init: ApiErrorInit) {
    super(init.message, init.cause === undefined ? undefined : { cause: init.cause });
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.details = init.details;
    this.retryAfter = init.retryAfter;
  }

  /** True for failures worth retrying with backoff: network errors, 429 and 5xx (R14). */
  get isRetryable(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500;
  }

  get isNetworkError(): boolean {
    return this.code === 'NETWORK_ERROR';
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

const KNOWN_CODES = new Set<string>([
  'VALIDATION_ERROR',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'NOT_FOUND',
  'CONFLICT',
  'GONE',
  'RATE_LIMITED',
  'PAYLOAD_TOO_LARGE',
  'QUOTA_EXCEEDED',
  'INTERNAL',
]);

function codeForStatus(status: number): ErrorCode {
  if (status === 400) return 'VALIDATION_ERROR';
  if (status === 401) return 'UNAUTHORIZED';
  if (status === 403) return 'FORBIDDEN';
  if (status === 404) return 'NOT_FOUND';
  if (status === 409) return 'CONFLICT';
  if (status === 410) return 'GONE';
  if (status === 413) return 'PAYLOAD_TOO_LARGE';
  if (status === 429) return 'RATE_LIMITED';
  return 'INTERNAL';
}

/** Retry-After (delta-seconds or HTTP-date) to whole seconds; undefined when absent or malformed. */
export function parseRetryAfter(
  value: string | null | undefined,
  now: number = Date.now(),
): number | undefined {
  if (value == null) return undefined;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, Math.ceil((at - now) / 1000));
}

export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

/**
 * `apiUrl('/me')` -> '/api/me'. Paths are relative to /api (a leading '/api/' is accepted too); absolute
 * http(s) URLs pass through. `baseUrl` is the origin for workers (e.g. self.location.origin).
 */
export function apiUrl(
  path: string,
  options: { baseUrl?: string; query?: QueryParams } = {},
): string {
  let url: string;
  if (/^https?:\/\//i.test(path)) {
    url = path;
  } else {
    const rel = path.startsWith('/') ? path : `/${path}`;
    const full =
      rel === API_PREFIX || rel.startsWith(`${API_PREFIX}/`) ? rel : `${API_PREFIX}${rel}`;
    url = `${(options.baseUrl ?? '').replace(/\/+$/, '')}${full}`;
  }
  if (options.query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(options.query)) {
      if (v !== undefined && v !== null && v !== '') params.append(k, String(v));
    }
    const qs = params.toString();
    if (qs) url += (url.includes('?') ? '&' : '?') + qs;
  }
  return url;
}

/** Build an ApiError from a non-2xx response (reads the `{error:{code,message,details}}` body if any). */
export async function errorFromResponse(res: Response): Promise<ApiError> {
  const retryAfter = parseRetryAfter(res.headers.get('retry-after'));
  let code: ErrorCode = codeForStatus(res.status);
  let message = res.statusText || `Request failed (HTTP ${res.status})`;
  let details: unknown;
  try {
    const body: unknown = await res.json();
    const err = (body as { error?: { code?: unknown; message?: unknown; details?: unknown } })
      ?.error;
    if (err && typeof err === 'object') {
      if (typeof err.code === 'string' && KNOWN_CODES.has(err.code)) code = err.code as ErrorCode;
      if (typeof err.message === 'string' && err.message) message = err.message;
      details = err.details;
    }
  } catch {
    // Not JSON (proxy error page, empty body): keep the status-derived code and message.
  }
  return new ApiError({ status: res.status, code, message, details, retryAfter });
}

/** Wrap a fetch rejection: AbortError passes through untouched, anything else is NETWORK_ERROR. */
export function networkError(err: unknown): unknown {
  if (err instanceof DOMException && err.name === 'AbortError') return err;
  if (err instanceof Error && err.name === 'AbortError') return err;
  return new ApiError({
    status: 0,
    code: 'NETWORK_ERROR',
    message: "Can't reach CipherDrop. Check your connection and try again.",
    cause: err,
  });
}

export interface BinaryRequestContext {
  /** Origin to prefix (workers may pass self.location.origin); default: same-origin relative URL. */
  baseUrl?: string;
  /** Capability bearer token (uploadToken). Never refreshed. */
  token?: string;
  signal?: AbortSignal;
}

/**
 * PUT raw ciphertext (chunk upload). Works in Web Workers: no auth store, no DOM.
 * Resolves on 2xx; rejects with ApiError (incl. retryAfter on 429) or an AbortError.
 */
export async function putBinary(
  path: string,
  body: ArrayBuffer | Uint8Array<ArrayBuffer>,
  headers: Record<string, string> = {},
  ctx: BinaryRequestContext = {},
): Promise<void> {
  const h = new Headers(headers);
  h.set('content-type', 'application/octet-stream');
  if (ctx.token) h.set('authorization', `Bearer ${ctx.token}`);
  let res: Response;
  try {
    res = await fetch(apiUrl(path, { baseUrl: ctx.baseUrl }), {
      method: 'PUT',
      body,
      headers: h,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctx.signal,
    });
  } catch (err) {
    throw networkError(err);
  }
  if (!res.ok) throw await errorFromResponse(res);
}
