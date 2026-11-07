/**
 * TanStack Query client and shared query keys (R22).
 *
 * Retry policy: never retry a 4xx (incl. 429: honour the server instead of hammering it) or a response that
 * failed schema validation; retry network errors and 5xx twice with backoff. Mutations never retry.
 * The auth store clears this cache on logout, so no decrypted data outlives a session.
 */
import { QueryClient } from '@tanstack/react-query';
import type { MeDropsStatus } from '@cipherdrop/shared';
import { isApiError } from './http';

export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  if (
    isApiError(error) &&
    (error.code === 'INVALID_RESPONSE' || (error.status >= 400 && error.status < 500))
  ) {
    return false;
  }
  return failureCount < 2;
}

export function retryDelay(attempt: number): number {
  return Math.min(500 * 4 ** attempt, 8_000);
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetryQuery,
        retryDelay,
        staleTime: 30_000,
        refetchOnWindowFocus: true,
      },
      mutations: { retry: false },
    },
  });
}

/** The app-wide client (AppProviders mounts it). */
export const queryClient = createQueryClient();

/**
 * R22: drop metadata is read once per page view. Refetching could race a consuming /open and flip the page to
 * "downloads used up" while the recipient is still downloading.
 */
export const dropMetaQueryOptions = {
  staleTime: Infinity,
  refetchOnWindowFocus: false,
  refetchOnReconnect: false,
} as const;

export interface PageParams {
  page: number;
  pageSize: number;
}

/**
 * Query keys shared by every lane so invalidation lines up. Call without arguments to get the prefix
 * for invalidateQueries (e.g. `queryKeys.myDrops()` matches every page and filter).
 */
export const queryKeys = {
  me: () => ['me'] as const,
  vault: () => ['auth', 'vault'] as const,
  sessions: () => ['auth', 'sessions'] as const,
  audit: (params?: PageParams & { action?: string }) =>
    params ? (['me', 'audit', params] as const) : (['me', 'audit'] as const),
  myDrops: (params?: PageParams & { status: MeDropsStatus }) =>
    params ? (['me', 'drops', params] as const) : (['me', 'drops'] as const),
  dropMeta: (dropId: string) => ['drops', dropId, 'meta'] as const,
  adminStats: () => ['admin', 'stats'] as const,
  adminReports: (params?: PageParams & { status?: string }) =>
    params ? (['admin', 'reports', params] as const) : (['admin', 'reports'] as const),
  adminUsers: (params?: PageParams & { search?: string }) =>
    params ? (['admin', 'users', params] as const) : (['admin', 'users'] as const),
} as const;
