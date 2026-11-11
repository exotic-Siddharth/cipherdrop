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

/**
 * Where an anonymous visitor on a guarded route goes. A deliberate sign-out or an account deletion lands on
 * the home page: the guard can still be mounted for one render after `logout()` while the navigation to `/`
 * commits, and it must not bounce that user to /login?next=<the page they just left>.
 */
function anonymousRedirect(
  reason: ReturnType<typeof useAuth.getState>['logoutReason'],
  returnPath: string,
): string {
  return reason === 'user' || reason === 'account-deleted' ? '/' : loginPath(returnPath);
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
  const logoutReason = useAuth((s) => s.logoutReason);
  const redirectToUnlock = useVault((s) => shouldRedirectToUnlock(s));
  const returnPath = useReturnPath();

  if (status === 'booting') return <PageLoader label="Restoring your session…" />;
  if (status !== 'authenticated') {
    return <Navigate to={anonymousRedirect(logoutReason, returnPath)} replace />;
  }
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
  const logoutReason = useAuth((s) => s.logoutReason);
  const returnPath = useReturnPath();

  if (status === 'booting') return <PageLoader label="Restoring your session…" />;
  if (status !== 'authenticated') {
    return <Navigate to={anonymousRedirect(logoutReason, returnPath)} replace />;
  }
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
