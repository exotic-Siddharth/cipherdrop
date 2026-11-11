import {
  AUDIT_ACTION_LABELS,
  AuditActionSchema,
  AuditEventPageSchema,
  type AuditAction,
  type AuditEventDto,
} from '@cipherdrop/shared';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { History } from 'lucide-react';
import { useState } from 'react';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { EmptyState, ErrorState } from '../../components/ui/EmptyState';
import { Pagination } from '../../components/ui/Pagination';
import { Select } from '../../components/ui/Select';
import { Skeleton } from '../../components/ui/Skeleton';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../../components/ui/Table';
import { api } from '../../lib/api';
import { cn } from '../../lib/cn';
import { formatDate, formatRelative } from '../../lib/format';
import { queryKeys } from '../../lib/queryClient';
import { AUDIT_PRESENTATION, TONE_CLASSES } from './auditPresentation';

export const ACTIVITY_PAGE_SIZE = 20;

const FILTER_OPTIONS = [
  { value: '', label: 'All activity' },
  ...AuditActionSchema.options.map((a) => ({ value: a, label: AUDIT_ACTION_LABELS[a] })),
];

function EventCell({ event }: { event: AuditEventDto }) {
  const { icon: Icon, tone } = AUDIT_PRESENTATION[event.action];
  return (
    <div className="flex items-center gap-3">
      <span
        className={cn(
          'inline-flex size-8 shrink-0 items-center justify-center rounded-lg',
          TONE_CLASSES[tone],
        )}
      >
        <Icon className="size-4" aria-hidden="true" />
      </span>
      <div className="min-w-0">
        <p className="font-medium text-foreground">{AUDIT_ACTION_LABELS[event.action]}</p>
        {/* On narrow screens the "where" column is hidden: show it under the event instead. */}
        <p className="mt-0.5 text-xs text-muted-strong sm:hidden">
          {[event.userAgent, event.ipPrefix].filter(Boolean).join(' · ') || 'Unknown device'}
        </p>
      </div>
    </div>
  );
}

/** Spec 11.2 Activity tab: audit table with human labels, an action filter and pagination. */
export function ActivityTab() {
  const [action, setAction] = useState<AuditAction | ''>('');
  const [page, setPage] = useState(1);

  const params = { page, pageSize: ACTIVITY_PAGE_SIZE, ...(action ? { action } : {}) };
  const audit = useQuery({
    queryKey: queryKeys.audit(params),
    queryFn: () => api.get('/me/audit', { query: params, schema: AuditEventPageSchema }),
    placeholderData: keepPreviousData,
  });

  const items = audit.data?.items ?? [];

  return (
    <Card as="section" aria-labelledby="activity-title">
      <CardHeader
        title={<span id="activity-title">Account activity</span>}
        description="Security events on your account. Locations are rounded to a network prefix, never an exact address."
        icon={History}
      />
      <CardContent className="flex flex-col gap-5 pt-5">
        <Select
          label="Show"
          containerClassName="max-w-xs"
          options={FILTER_OPTIONS}
          value={action}
          onChange={(e) => {
            setAction(e.target.value as AuditAction | '');
            setPage(1);
          }}
        />

        {audit.isPending ? (
          <div className="flex flex-col gap-3" aria-busy="true" aria-label="Loading activity">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : audit.isError ? (
          <ErrorState
            title="We could not load your activity"
            error={audit.error}
            onRetry={() => void audit.refetch()}
            retrying={audit.isFetching}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={History}
            size="sm"
            bordered
            title="Nothing here yet"
            description={
              action
                ? 'No events of this kind. Try another filter.'
                : 'Events will show up as you use your account.'
            }
          />
        ) : (
          <div
            className={cn(
              '-mx-5 border-y border-border sm:mx-0 sm:rounded-lg sm:border',
              audit.isPlaceholderData && 'opacity-60 transition-opacity',
            )}
          >
            <Table>
              <TableCaption className="sr-only">Recent account events</TableCaption>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Event</TableHead>
                  <TableHead className="hidden sm:table-cell">Where</TableHead>
                  <TableHead className="text-right">When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell>
                      <EventCell event={event} />
                    </TableCell>
                    <TableCell className="hidden text-muted sm:table-cell">
                      <span className="block max-w-56 truncate">
                        {event.userAgent ?? 'Unknown device'}
                      </span>
                      {event.ipPrefix ? (
                        <span className="block font-mono text-xs text-muted-strong">
                          {event.ipPrefix}
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right text-muted">
                      <time dateTime={event.createdAt} title={formatDate(event.createdAt)}>
                        {formatRelative(event.createdAt)}
                      </time>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {audit.data ? (
          <Pagination
            page={page}
            pageSize={ACTIVITY_PAGE_SIZE}
            total={audit.data.total}
            onPageChange={setPage}
            label="Activity pages"
          />
        ) : null}
      </CardContent>
    </Card>
  );
}
