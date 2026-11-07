import { useEffect, useRef } from 'react';
import { ScrollRestoration, useLocation, useMatches } from 'react-router';
import { PageLoader } from '../ui/Spinner';
import { AppShell } from './AppShell';
import { documentTitle, type RouteHandle } from './routeHandle';

/** document.title from the deepest route `handle.title`. */
function useRouteTitle() {
  const matches = useMatches();
  const title = [...matches]
    .reverse()
    .map((m) => (m.handle as RouteHandle | undefined)?.title)
    .find(Boolean);
  useEffect(() => {
    document.title = documentTitle(title);
  }, [title]);
}

/** After client-side navigation move focus to <main>, so screen readers start at the new page. */
function useFocusMainOnNavigate() {
  const { pathname } = useLocation();
  const previous = useRef(pathname);
  useEffect(() => {
    if (previous.current === pathname) return;
    previous.current = pathname;
    document.getElementById('main')?.focus({ preventScroll: true });
  }, [pathname]);
}

/** Root route element: the shell around every page. */
export function RootLayout() {
  useRouteTitle();
  useFocusMainOnNavigate();
  return (
    <>
      <AppShell />
      <ScrollRestoration />
    </>
  );
}

/** Shown while the first lazy route module loads (React Router HydrateFallback). */
export function RootHydrateFallback() {
  return (
    <AppShell>
      <PageLoader />
    </AppShell>
  );
}
