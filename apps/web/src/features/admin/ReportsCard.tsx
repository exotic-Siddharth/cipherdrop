import {
  AdminReportPageSchema,
  type AdminReport,
  type AdminResolveRequest,
  type ReportReason,
  type ReportStatus,
} from '@cipherdrop/shared';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, CircleCheck, Eye, EyeOff, Flag, KeyRound, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Badge, type BadgeTone } from '../../components/ui/Badge';
import { Button, ButtonLink } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { ConfirmDialog } from '../../components/ui/Dialog';
import { EmptyState, ErrorState } from '../../components/ui/EmptyState';
import { Pagination } from '../../components/ui/Pagination';
import { Skeleton } from '../../components/ui/Skeleton';
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/Tabs';
import { api } from '../../lib/api';
import { cn } from '../../lib/cn';
import { formatBytes, formatDate, formatRelative, pluralize } from '../../lib/format';
import { reviewPath } from '../../lib/links';
import { queryKeys } from '../../lib/queryClient';
import { StatusBadge } from '../dashboard/components/StatusBadge';

const PAGE_SIZE = 10;

type Filter = 'OPEN' | 'RESOLVED' | 'DISMISSED' | 'ALL';
const FILTERS: ReadonlyArray<{ value: Filter; label: string }> = [
  { value: 'OPEN', label: 'Open' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'DISMISSED', label: 'Dismissed' },
  { value: 'ALL', label: 'All' },
];

const REASON_LABEL: Record<ReportReason, string> = {
  MALWARE: 'Malware',
  PHISHING: 'Phishing',
  ILLEGAL: 'Illegal content',
  COPYRIGHT: 'Copyright',
  OTHER: 'Other',
};
const REPORT_STATUS: Record<ReportStatus, { label: string; tone: BadgeTone }> = {
  OPEN: { label: 'Open', tone: 'warning' },
  RESOLVED: { label: 'Resolved', tone: 'success' },
  DISMISSED: { label: 'Dismissed', tone: 'neutral' },
};

/** A usable reviewer key: exactly the 43-char base64url form of a 32-byte drop key. */
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;

function isFilter(value: string): value is Filter {
  return FILTERS.some((f) => f.value === value);
}

interface PendingAction {
  report: AdminReport;
  action: AdminResolveRequest['action'];
}

function ReportActions({
  report,
  onAct,
}: {
  report: AdminReport;
  onAct: (p: PendingAction) => void;
}) {
  const open = report.status === 'OPEN';
  const key =
    report.hasKey && report.decryptionKey && KEY_RE.test(report.decryptionKey)
      ? report.decryptionKey
      : null;
  const dropGone = report.drop.status === 'DELETED' || report.drop.status === 'DISABLED';
  return (
    <div className="flex flex-wrap items-center gap-2 lg:justify-end">
      {key ? (
        <ButtonLink
          to={reviewPath(report.drop.id, key)}
          variant="outline"
          size="sm"
          icon={Eye}
          aria-label={`Review drop ${report.drop.id}`}
        >
          Review
        </ButtonLink>
      ) : (
        <Button
          variant="outline"
          size="sm"
          icon={EyeOff}
          disabled
          title="The reporter did not include the decryption key"
          aria-label={`Review drop ${report.drop.id} (no key supplied)`}
        >
          Review
        </Button>
      )}
      {open ? (
        <>
          <Button
            variant="danger"
            size="sm"
            icon={Ban}
            disabled={dropGone}
            title={dropGone ? 'This drop is already offline' : undefined}
            onClick={() => onAct({ report, action: 'DISABLE_DROP' })}
            aria-label={`Disable drop ${report.drop.id}`}
          >
            Disable
          </Button>
          <Button
            variant="ghost"
            size="sm"
            icon={X}
            onClick={() => onAct({ report, action: 'DISMISS' })}
            aria-label={`Dismiss report ${report.id}`}
          >
            Dismiss
          </Button>
        </>
      ) : null}
    </div>
  );
}

/** Abuse report queue (spec 10 and 11.2, R13): Review opens /d/:id?review=1#<key>; Disable and Dismiss confirm. */
export function ReportsCard() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<Filter>('OPEN');
  const [page, setPage] = useState(1);
  const [pending, setPending] = useState<PendingAction | null>(null);

  const reports = useQuery({
    queryKey: queryKeys.adminReports({
      page,
      pageSize: PAGE_SIZE,
      ...(filter === 'ALL' ? {} : { status: filter }),
    }),
    queryFn: () =>
      api.get('/admin/reports', {
        schema: AdminReportPageSchema,
        query: { page, pageSize: PAGE_SIZE, status: filter === 'ALL' ? undefined : filter },
      }),
    placeholderData: keepPreviousData,
  });

  useEffect(() => {
    if (reports.data && reports.data.items.length === 0 && page > 1) setPage(page - 1);
  }, [reports.data, page]);

  const resolve = useMutation({
    mutationFn: ({ report, action }: PendingAction) =>
      api.post(`/admin/reports/${encodeURIComponent(report.id)}/resolve`, { action }),
    onSuccess: (_data, { action }) => {
      toast.success(
        action === 'DISABLE_DROP' ? 'Drop disabled and report resolved' : 'Report dismissed',
      );
      void qc.invalidateQueries({ queryKey: queryKeys.adminReports() });
      void qc.invalidateQueries({ queryKey: queryKeys.adminStats() });
    },
  });

  const items = reports.data?.items ?? [];
  const disabling = pending?.action === 'DISABLE_DROP';

  return (
    <Card as="section" aria-labelledby="reports-title">
      <CardHeader
        icon={Flag}
        title={<span id="reports-title">Abuse reports</span>}
        description="Review needs the key the reporter chose to include. Moderators never see keys otherwise."
      />
      <div className="px-5 pt-4 sm:px-6">
        <Tabs
          value={filter}
          onValueChange={(v) => {
            if (!isFilter(v)) return;
            setFilter(v);
            setPage(1);
          }}
          variant="pills"
        >
          <TabsList aria-label="Filter reports">
            {FILTERS.map((f) => (
              <TabsTrigger key={f.value} value={f.value}>
                {f.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      <div className="mt-4 border-t border-border">
        {reports.isPending ? (
          <div className="space-y-3 p-5" aria-hidden="true">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : reports.isError ? (
          <ErrorState
            title="Couldn't load reports"
            error={reports.error}
            onRetry={() => void reports.refetch()}
            retrying={reports.isFetching}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={CircleCheck}
            tone="success"
            size="sm"
            title={filter === 'OPEN' ? 'No open reports' : 'No reports here'}
            description={
              filter === 'OPEN'
                ? 'The queue is clear. New reports appear here as they come in.'
                : 'Nothing matches this filter.'
            }
          />
        ) : (
          <ul
            aria-label="Abuse reports"
            aria-busy={reports.isPlaceholderData}
            className={cn('divide-y divide-border', reports.isPlaceholderData && 'opacity-70')}
          >
            {items.map((r) => (
              <li
                key={r.id}
                className="grid gap-x-6 gap-y-3 p-4 sm:p-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)_auto] lg:items-start"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-foreground">{REASON_LABEL[r.reason]}</span>
                    {r.status !== 'OPEN' ? (
                      <Badge tone={REPORT_STATUS[r.status].tone}>
                        {REPORT_STATUS[r.status].label}
                      </Badge>
                    ) : null}
                  </div>
                  {r.details ? (
                    <p
                      className="mt-1 line-clamp-3 break-words text-sm text-muted-strong"
                      title={r.details}
                    >
                      {r.details}
                    </p>
                  ) : null}
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="break-all font-mono text-xs text-foreground">{r.drop.id}</code>
                    <StatusBadge status={r.drop.status} />
                  </div>
                  <p className="mt-1 break-all text-xs text-muted-strong">
                    {pluralize(r.drop.fileCount, 'file')} · {formatBytes(r.drop.totalBytes)} ·{' '}
                    {r.drop.ownerEmail ?? 'anonymous owner'}
                  </p>
                  <p className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted-strong">
                    {r.hasKey ? (
                      <Badge tone="primary" icon={KeyRound}>
                        Has key
                      </Badge>
                    ) : (
                      <Badge tone="neutral">No key</Badge>
                    )}
                    <span title={formatDate(r.createdAt)}>
                      Reported {formatRelative(r.createdAt)}
                    </span>
                  </p>
                </div>
                <ReportActions report={r} onAct={setPending} />
              </li>
            ))}
          </ul>
        )}
      </div>

      {reports.isSuccess && reports.data.total > 0 ? (
        <div className="border-t border-border p-4 sm:p-5">
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={reports.data.total}
            onPageChange={setPage}
            label="Report pages"
          />
        </div>
      ) : null}

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => {
          if (!open) setPending(null);
        }}
        tone={disabling ? 'danger' : 'default'}
        title={disabling ? 'Disable this drop?' : 'Dismiss this report?'}
        description={
          disabling
            ? 'Its encrypted files are deleted immediately and the link stops working. The report is marked resolved. This cannot be undone.'
            : 'The drop stays online and the report is closed as dismissed.'
        }
        confirmLabel={disabling ? 'Disable drop' : 'Dismiss report'}
        onConfirm={async () => {
          if (pending) await resolve.mutateAsync(pending);
        }}
      />
    </Card>
  );
}
