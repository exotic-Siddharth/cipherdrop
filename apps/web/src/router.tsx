/**
 * Routes (spec 11.2). S5 owns this file; lanes own the page modules it lazy-loads.
 *
 * React Router "Component export convention" (R22): every page module exports `Component` (and optionally
 * `ErrorBoundary`) and nothing that collides with a route property. Titles live here in `handle`, not in the
 * modules. Guards: RequireAuth (signed in), RequireAuth needsVault (dashboard: R7 boot redirect to
 * /unlock?next=), RequireAdmin (role ADMIN, 403 state otherwise).
 */
import { createBrowserRouter, type RouteObject } from 'react-router';
import { AdminLayout } from './components/layout/AdminLayout';
import { RootHydrateFallback, RootLayout } from './components/layout/RootLayout';
import type { RouteHandle } from './components/layout/routeHandle';
import { RouteErrorBoundary } from './components/RouteErrorBoundary';
import { RequireAdmin, RequireAuth } from './components/RouteGuards';

const titled = (title: string): RouteHandle => ({ title });

export const routes: RouteObject[] = [
  {
    id: 'root',
    Component: RootLayout,
    HydrateFallback: RootHydrateFallback,
    ErrorBoundary: RouteErrorBoundary,
    children: [
      {
        index: true,
        handle: titled('Send files'),
        lazy: () => import('./features/send/SendPage'),
      },
      {
        path: 'd/:id',
        handle: titled('Receive files'),
        lazy: () => import('./features/receive/ReceivePage'),
      },
      {
        path: 'how-it-works',
        handle: titled('How it works'),
        lazy: () => import('./features/howitworks/HowItWorksPage'),
      },
      { path: 'login', handle: titled('Log in'), lazy: () => import('./features/auth/LoginPage') },
      {
        path: 'register',
        handle: titled('Create account'),
        lazy: () => import('./features/auth/RegisterPage'),
      },
      {
        path: 'recover',
        handle: titled('Recover account'),
        lazy: () => import('./features/auth/RecoverPage'),
      },
      {
        Component: RequireAuth,
        children: [
          {
            path: 'unlock',
            handle: titled('Unlock vault'),
            lazy: () => import('./features/auth/UnlockPage'),
          },
          {
            path: 'settings',
            handle: titled('Settings'),
            lazy: () => import('./features/settings/SettingsPage'),
          },
        ],
      },
      {
        element: <RequireAuth needsVault />,
        children: [
          {
            path: 'dashboard',
            handle: titled('Dashboard'),
            lazy: () => import('./features/dashboard/DashboardPage'),
          },
        ],
      },
      {
        Component: RequireAdmin,
        children: [
          {
            path: 'admin',
            Component: AdminLayout,
            children: [
              {
                index: true,
                handle: titled('Admin'),
                lazy: () => import('./features/admin/AdminPage'),
              },
            ],
          },
        ],
      },
      {
        path: '*',
        handle: titled('Page not found'),
        lazy: () => import('./features/NotFoundPage'),
      },
    ],
  },
];

export function createAppRouter() {
  return createBrowserRouter(routes);
}
