import type { ReactNode } from 'react';
import { Outlet, useNavigation } from 'react-router';
import { Footer } from './Footer';
import { Navbar } from './Navbar';

/** Thin top bar while a route (or its lazy chunk) is loading. */
function TopProgress() {
  const navigation = useNavigation();
  if (navigation.state === 'idle') return null;
  return (
    <div
      role="progressbar"
      aria-label="Loading page"
      className="fixed inset-x-0 top-0 z-[70] h-0.5 overflow-hidden bg-primary/15"
    >
      <div className="h-full w-2/5 bg-primary motion-safe:animate-progress-indeterminate" />
    </div>
  );
}

export interface AppShellProps {
  /** Page content; defaults to the matched child route (<Outlet />). */
  children?: ReactNode;
}

/**
 * Page frame: skip link, navbar, the <main> landmark (max-w-6xl, page padding) and footer. Pages render inside
 * <main> and start with a PageHeader.
 */
export function AppShell({ children }: AppShellProps) {
  return (
    <div className="flex min-h-dvh flex-col">
      {/* Focuses <main> without touching location.hash (the hash may hold a drop key). */}
      <a
        href="#main"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById('main')?.focus();
        }}
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-[80] focus:rounded-lg focus:bg-surface focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:shadow-popover"
      >
        Skip to content
      </a>
      <TopProgress />
      <Navbar />
      <main
        id="main"
        tabIndex={-1}
        className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 outline-none sm:px-6 sm:py-12"
      >
        {children ?? <Outlet />}
      </main>
      <Footer />
    </div>
  );
}
