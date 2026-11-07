import { ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { Outlet } from 'react-router';

export interface AdminLayoutProps {
  /** Content; defaults to the child route (<Outlet />). */
  children?: ReactNode;
}

/** Frame of the admin console (/admin, behind RequireAdmin): a restricted-area banner above the page. */
export function AdminLayout({ children }: AdminLayoutProps) {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1 rounded-xl border border-warning/30 bg-warning/5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
        <p className="flex items-center gap-2 text-sm font-semibold text-foreground">
          <ShieldCheck className="size-4 text-warning" aria-hidden="true" />
          Admin console
        </p>
        <p className="text-xs text-muted-strong">
          Restricted area. Review grants and moderation actions are recorded in the audit log.
        </p>
      </div>
      {children ?? <Outlet />}
    </div>
  );
}
