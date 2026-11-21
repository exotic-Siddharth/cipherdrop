import {
  AUDIT_ACTION_LABELS,
  AdminAuditPageSchema,
  type AdminAuditEvent,
  type AdminAuditQuery,
} from '@cipherdrop/shared';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { ScrollText } from 'lucide-react';
import { useState } from 'react';
import { Card, CardHeader } from '../../components/ui/Card';
import { EmptyState, ErrorState } from '../../components/ui/EmptyState';
import { Pagination } from '../../components/ui/Pagination';
import { Select } from '../../components/ui/Select';
import { Skeleton } from '../../components/ui/Skeleton';
import { api } from '../../lib/api';
import { cn } from '../../lib/cn';
import { formatDate, formatRelative } from '../../lib/format';
import { queryKeys } from '../../lib/queryClient';
import { AUDIT_PRESENTATION } from '../settings/auditPresentation';

const PAGE_SIZE = 10;

type Scope = AdminAuditQuery['scope'];

const SCOPE_OPTIONS = [
  { value: 'admin', label: 'Admin actions' },
  { value: 'all', label: 'All events' },
] as const;

const isScope = (value: string): value is Scope => value === 'admin' || value === 'all';

function actorText(e: AdminAuditEvent): string | null {
  if (e.byOperator) return 'Operator (command line)';
  if (e.actor) return e.actor.email;
  return null;
}

/** The reason an admin gave, or a role or quota change, in one line. Never shows keys (none are stored). */
function detailText(e: AdminAuditEvent): string | null {
  const m = e.metadata ?? {};
  const parts: string[] = [];
  if (typeof m.reason === 'string') parts.push(`Reason: ${m.reason}`);
  const role = m.role as { from?: unknown; to?: unknown } | undefined;
  if (role && typeof role.from === 'string' && typeof role.to === 'string') {
    parts.push(`Role ${role.from} to ${role.to}`);
  }
  if (m.storageQuotaBytes) parts.push('Storage quota changed');
  if (typeof m.revokedSessions === 'number') parts.push(`${m.revokedSessions} sessions signed out`);
  if (m.allUsers === true) parts.push('All accounts');
  return parts.length ? parts.join(' · ') : null;
}

/** Instance audit log (server-4): who did what, newest first. Admin actions by default. */
export function AuditCard() {
  const [scope, setScope] = useState<Scope>('admin');
  const [page, setPage] = useState(1);

  const audit = useQuery({
    queryKey: queryKeys.adminAudit({ page, pageSize: PAGE_SIZE, scope }),
    queryFn: () =>
      api.get('/admin/audit', {
        schema: AdminAuditPageSchema,
        query: { page, pageSize: PAGE_SIZE, scope },
      }),
    placeholderData: keepPreviousData,
  });
  const items = audit.data?.items ?? [];

  return (
    <Card as="section" aria-labelledby="audit-title">
      <CardHeader
        icon={ScrollText}
        title={<span id="audit-title">Audit</span>}
        description="Every admin and operator action, with who did it. Kept for a year."
      />
      <div className="px-5 pt-4 sm:px-6">
        <Select
          label="Show"
          value={scope}
          onChange={(e) => {
            if (isScope(e.target.value)) {
              setScope(e.target.value);
              setPage(1);
            }
          }}
          options={SCOPE_OPTIONS}
          containerClassName="max-w-xs"
        />
      </div>
      <div className="mt-4 border-t border-border">
        {audit.isPending ? (
          <div className="space-y-3 p-5" aria-hidden="true">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : audit.isError ? (
          <ErrorState
            title="Couldn't load the audit log"
            error={audit.error}
            onRetry={() => void audit.refetch()}
            retrying={audit.isFetching}
          />
        ) : items.length === 0 ? (
          <EmptyState icon={ScrollText} size="sm" title="No events yet" />
        ) : (
          <ul
            aria-label="Audit events"
            aria-busy={audit.isPlaceholderData}
            className={cn('divide-y divide-border', audit.isPlaceholderData && 'opacity-70')}
          >
            {items.map((e) => {
              const { icon: Icon } = AUDIT_PRESENTATION[e.action];
              const actor = actorText(e);
              const detail = detailText(e);
              return (
                <li key={e.id} className="flex gap-3 p-4 sm:p-5">
                  <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-strong" />
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-foreground">{AUDIT_ACTION_LABELS[e.action]}</p>
                    <p className="mt-0.5 break-all text-sm text-muted-strong">
                      {actor ? <>By {actor}</> : null}
                      {actor && e.subject ? ' · ' : null}
                      {e.subject ? <>Account {e.subject.email ?? 'deleted'}</> : null}
                      {e.dropId ? <> · Drop {e.dropId}</> : null}
                    </p>
                    {detail ? <p className="mt-0.5 text-sm text-muted-strong">{detail}</p> : null}
                    <p className="mt-0.5 text-xs text-muted-strong">
                      <time dateTime={e.createdAt} title={formatDate(e.createdAt)}>
                        {formatRelative(e.createdAt)}
                      </time>
                      {e.ipPrefix ? <> · {e.ipPrefix}</> : null}
                      {e.userAgent ? <> · {e.userAgent}</> : null}
                    </p>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
      {audit.isSuccess && audit.data.total > 0 ? (
        <div className="border-t border-border p-4 sm:p-5">
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={audit.data.total}
            onPageChange={setPage}
            label="Audit pages"
          />
        </div>
      ) : null}
    </Card>
  );
}
