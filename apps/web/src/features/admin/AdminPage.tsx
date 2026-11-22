import { AdminStatsSchema } from '@cipherdrop/shared';
import { useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { AdminMfaRequired } from '../../components/RouteGuards';
import { Card } from '../../components/ui/Card';
import { ErrorState } from '../../components/ui/EmptyState';
import { Skeleton } from '../../components/ui/Skeleton';
import { api } from '../../lib/api';
import { isMfaRequired } from '../../lib/errors';
import { queryKeys } from '../../lib/queryClient';
import { AuditCard } from './AuditCard';
import { ReportsCard } from './ReportsCard';
import { StatsCards } from './StatsCards';
import { TakedownCard } from './TakedownCard';
import { UploadsChart } from './UploadsChart';
import { UsersCard } from './UsersCard';

function StatsSkeleton() {
  return (
    <div aria-hidden="true" className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-5">
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-80 rounded-xl" />
    </div>
  );
}

/**
 * Admin console (spec 10, 11.2): stats + uploads chart, report queue, takedown by id, users, audit log (server-4,
 * server-6). Renders inside AdminLayout.
 */
export function Component() {
  const stats = useQuery({
    queryKey: queryKeys.adminStats(),
    queryFn: () => api.get('/admin/stats', { schema: AdminStatsSchema }),
  });

  // The session's user said 2FA was on, but the API disagrees (turned off in another tab): show the same notice
  // as the route guard instead of three error cards.
  if (stats.isError && isMfaRequired(stats.error)) return <AdminMfaRequired />;

  return (
    <>
      <PageHeader
        title="Admin"
        description="Statistics, abuse reports, takedowns, users and the audit log."
        icon={ShieldCheck}
        className="mb-0"
      />
      {stats.isPending ? (
        <StatsSkeleton />
      ) : stats.isError ? (
        <Card>
          <ErrorState
            title="Couldn't load statistics"
            error={stats.error}
            onRetry={() => void stats.refetch()}
            retrying={stats.isFetching}
          />
        </Card>
      ) : (
        <>
          <StatsCards stats={stats.data} />
          <UploadsChart days={stats.data.uploadsLast14d} />
        </>
      )}
      <ReportsCard />
      <TakedownCard />
      <UsersCard />
      <AuditCard />
    </>
  );
}
