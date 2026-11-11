/**
 * Test helpers for the account pages (W1). Not imported by app code.
 *
 * - installInProcessKdfWorker(): replaces the Worker global so kdfClient runs the REAL worker logic (real
 *   Argon2id, real WebCrypto) in-process, with messages structured-cloned like a real worker.
 * - mockApi(): a fetch stub keyed by "METHOD /api/path" that records every call.
 */
import type { AuthSuccess, Me } from '@cipherdrop/shared';
import { QueryClientProvider } from '@tanstack/react-query';
import { configure, render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { createMemoryRouter, RouterProvider, type RouteObject } from 'react-router';
import { vi } from 'vitest';
import { resetKdfWorker } from '../../crypto/kdfClient';
import {
  handleKdfRequest,
  serializeKdfError,
  type KdfRequestMessage,
} from '../../workers/kdf.worker';
import { queryClient } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';

// Argon2id runs for real in these tests and the machine may be busy: be generous with waits.
vi.setConfig({ testTimeout: 40_000 });
configure({ asyncUtilTimeout: 20_000 });

class InProcessWorker {
  private listeners: Record<string, Array<(ev: unknown) => void>> = {};
  addEventListener(type: string, fn: (ev: unknown) => void) {
    (this.listeners[type] ??= []).push(fn);
  }
  removeEventListener() {}
  terminate() {}
  postMessage(raw: KdfRequestMessage) {
    const msg = structuredClone(raw);
    void handleKdfRequest(msg.request).then(
      (result) => this.reply({ id: msg.id, ok: true, result }),
      (err: unknown) => this.reply({ id: msg.id, ok: false, error: serializeKdfError(err) }),
    );
  }
  private reply(data: unknown) {
    const cloned = structuredClone(data);
    setTimeout(() => this.listeners['message']?.forEach((fn) => fn({ data: cloned })), 0);
  }
}

export function installInProcessKdfWorker(): void {
  vi.stubGlobal('Worker', InProcessWorker);
  resetKdfWorker();
}

export const TEST_ME: Me = {
  id: 'user_test_1',
  email: 'ada@example.com',
  role: 'USER',
  totpEnabled: false,
  autoLockMinutes: 15,
  storageQuotaBytes: 1_000_000_000,
  storageUsedBytes: 12_345_678,
  createdAt: '2026-11-07T10:00:00.000Z',
};

export function authSuccess(overrides: Partial<Me> = {}): AuthSuccess {
  return { user: { ...TEST_ME, ...overrides }, accessToken: 'test-access-token' };
}

export function signIn(overrides: Partial<Me> = {}): void {
  useAuth.setState({
    status: 'authenticated',
    user: { ...TEST_ME, ...overrides },
    accessToken: 'test-access-token',
    accessTokenExpiresAt: Date.now() + 600_000,
  });
}

export function resetStores(): void {
  useAuth.setState(useAuth.getInitialState(), true);
  useVault.setState(useVault.getInitialState(), true);
  queryClient.clear();
}

export interface RecordedCall {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
  headers: Headers;
}

export type MockHandler =
  | { status?: number; json?: unknown; headers?: Record<string, string> }
  | ((call: RecordedCall) => { status?: number; json?: unknown; headers?: Record<string, string> });

/** Stub fetch. Keys look like "POST /api/auth/login". An unmatched request fails the test loudly. */
export function mockApi(handlers: Record<string, MockHandler>) {
  const calls: RecordedCall[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers);
    let body: unknown = undefined;
    if (typeof init?.body === 'string') body = JSON.parse(init.body) as unknown;
    const call: RecordedCall = {
      method,
      path: url.pathname,
      query: url.searchParams,
      body,
      headers,
    };
    calls.push(call);
    const handler = handlers[`${method} ${url.pathname}`];
    if (!handler) throw new Error(`Unexpected request: ${method} ${url.pathname}`);
    const out = typeof handler === 'function' ? handler(call) : handler;
    const status = out.status ?? 200;
    if (status === 204 || out.json === undefined) {
      return new Response(null, { status, headers: out.headers });
    }
    return new Response(JSON.stringify(out.json), {
      status,
      headers: { 'content-type': 'application/json', ...out.headers },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls, fetchMock };
}

export function apiError(status: number, code: string, message: string) {
  return { status, json: { error: { code, message } } };
}

/** Render `routes` at `path` inside the app's QueryClientProvider. */
export function renderRoutes(
  routes: RouteObject[],
  path: string,
): ReturnType<typeof createMemoryRouter> {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  const ui: ReactElement = (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
  render(ui);
  return router;
}
