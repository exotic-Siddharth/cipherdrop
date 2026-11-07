import { LayoutDashboard, ShieldOff } from 'lucide-react';
import type { ReactNode } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router';
import { loginPath, unlockPath } from '../lib/paths';
import { useAuth } from '../stores/auth';
import { shouldRedirectToUnlock, useVault } from '../stores/vault';
import { ButtonLink } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { PageLoader } from './ui/Spinner';

/**
 * Where to come back to after login/unlock. Pathname + search ONLY: the #fragment can hold a drop key, and a
 * key must never be copied into a query string (query strings reach servers and logs).
 */
function useReturnPath(): string {
  const { pathname, search } = useLocation();
  return `${pathname}${search}`;
}

export interface RequireAuthProps {
  /**
   * The route needs the unlocked vault (the dashboard). R7: only a boot without a key redirects to
   * /unlock?next=; after an in-place auto-lock the page stays and shows its locked state.
   */
  needsVault?: boolean;
  /** Content to guard; defaults to the child routes (<Outlet />). */
  children?: ReactNode;
}

/** Signed-in routes: waits for the boot refresh, then sends anonymous visitors to /login?next=. */
export function RequireAuth({ needsVault = false, children }: RequireAuthProps) {
  const status = useAuth((s) => s.status);
  const redirectToUnlock = useVault((s) => shouldRedirectToUnlock(s));
  const returnPath = useReturnPath();

  if (status === 'booting') return <PageLoader label="Restoring your session…" />;
  if (status !== 'authenticated') return <Navigate to={loginPath(returnPath)} replace />;
  if (needsVault && redirectToUnlock) return <Navigate to={unlockPath(returnPath)} replace />;
  return children ?? <Outlet />;
}

export interface RequireAdminProps {
  children?: ReactNode;
}

/** Admin routes: like RequireAuth, plus a 403 state for non-admins (the API re-checks the role anyway). */
export function RequireAdmin({ children }: RequireAdminProps) {
  const status = useAuth((s) => s.status);
  const role = useAuth((s) => s.user?.role);
  const returnPath = useReturnPath();

  if (status === 'booting') return <PageLoader label="Restoring your session…" />;
  if (status !== 'authenticated') return <Navigate to={loginPath(returnPath)} replace />;
  if (role !== 'ADMIN') {
    return (
      <EmptyState
        icon={ShieldOff}
        tone="warning"
        titleAs="h1"
        title="Admins only"
        description="Your account does not have access to the moderation console."
        action={
          <ButtonLink to="/dashboard" variant="outline" icon={LayoutDashboard}>
            Go to your dashboard
          </ButtonLink>
        }
      />
    );
  }
  return children ?? <Outlet />;
}
