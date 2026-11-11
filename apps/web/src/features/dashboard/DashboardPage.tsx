import {
  MeResponseSchema,
  OwnerDropPageSchema,
  type MeDropsStatus,
  type OwnerDropSummary,
} from '@cipherdrop/shared';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { FilePlus2, LayoutDashboard, LockKeyhole } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useLocation } from 'react-router';
import { toast } from 'sonner';
import { PageHeader } from '../../components/layout/PageHeader';
import { Alert } from '../../components/ui/Alert';
import { ButtonLink } from '../../components/ui/Button';
import { Card } from '../../components/ui/Card';
import { ConfirmDialog } from '../../components/ui/Dialog';
import { EmptyState, ErrorState } from '../../components/ui/EmptyState';
import { Pagination } from '../../components/ui/Pagination';
import { Skeleton } from '../../components/ui/Skeleton';
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/Tabs';
import { api } from '../../lib/api';
import { copyText } from '../../lib/clipboard';
import { shareLinkFor, unlockPath } from '../../lib/links';
import { queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';
import { DropRow } from './components/DropRow';
import { StorageMeter } from './components/StorageMeter';
import { useOwnerDropNames } from './useOwnerDropNames';

const PAGE_SIZE = 10;

const FILTERS: ReadonlyArray<{ value: MeDropsStatus; label: string }> = [
  { value: 'active', label: 'Active' },
  { value: 'expired', label: 'Expired' },
  { value: 'all', label: 'All' },
];

const EMPTY_COPY: Record<MeDropsStatus, { title: string; description: string }> = {
  active: {
    title: 'No active drops',
    description:
      'Drops you send while signed in show up here, with their names decrypted on this device.',
  },
  expired: {
    title: 'Nothing has expired yet',
    description: 'Drops that expired, ran out of downloads or were disabled are listed here.',
  },
  all: {
    title: 'No drops yet',
    description:
      'Send your first drop. Only you and the people you share the link with can read it.',
  },
};

function isFilter(value: string): value is MeDropsStatus {
  return FILTERS.some((f) => f.value === value);
}

function ListSkeleton() {
  return (
    <div role="status" className="divide-y divide-border">
      <span className="sr-only">Loading your drops…</span>
      {[0, 1, 2].map((i) => (
        <div key={i} aria-hidden="true" className="flex items-center gap-3 p-5">
          <Skeleton className="size-9 rounded-lg" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-48 max-w-full" />
            <Skeleton className="h-3 w-32" />
          </div>
          <Skeleton className="hidden h-6 w-24 sm:block" />
        </div>
      ))}
    </div>
  );
}

/** Owner dashboard (spec 11.2): storage meter, filtered drop list with locally decrypted names. */
export function Component() {
  const qc = useQueryClient();
  const location = useLocation();
  const user = useAuth((s) => s.user);
  const setUser = useAuth((s) => s.setUser);
  const accountKey = useVault((s) => s.accountKey);

  const [status, setStatus] = useState<MeDropsStatus>('active');
  const [page, setPage] = useState(1);
  const [toDelete, setToDelete] = useState<OwnerDropSummary | null>(null);

  const drops = useQuery({
    queryKey: queryKeys.myDrops({ page, pageSize: PAGE_SIZE, status }),
    queryFn: () =>
      api.get('/me/drops', {
        schema: OwnerDropPageSchema,
        query: { status, page, pageSize: PAGE_SIZE },
      }),
    placeholderData: keepPreviousData,
    // Recipients change a drop's state (downloads used up, expired) behind the owner's back: revalidate when a
    // filter tab is shown again instead of trusting a list that is up to 30 s old.
    staleTime: 0,
  });
  const items = drops.data?.items ?? [];
  const nameOf = useOwnerDropNames(items, accountKey);

  // Deleting the last row of a page (or the list shrinking elsewhere) must not strand us on an empty page.
  useEffect(() => {
    if (drops.data && drops.data.items.length === 0 && page > 1) setPage(page - 1);
  }, [drops.data, page]);

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/drops/${encodeURIComponent(id)}`),
    onSuccess: async () => {
      toast.success('Drop deleted');
      void qc.invalidateQueries({ queryKey: queryKeys.myDrops() });
      try {
        const me = await api.get('/me', { schema: MeResponseSchema });
        setUser(me.user);
      } catch {
        // The meter keeps its last value; the next navigation refreshes it.
      }
    },
  });

  const onCopy = async (drop: OwnerDropSummary) => {
    const state = nameOf(drop.id);
    let link: string | null = null;
    if (drop.passwordProtected) link = shareLinkFor(drop.id, null);
    else if (state.kind === 'ready') link = shareLinkFor(drop.id, state.dk);
    if (!link) {
      toast.error('Unlock your vault to rebuild this link.');
      return;
    }
    const ok = await copyText(link);
    if (!ok) toast.error('Could not copy. Select the link and copy it manually.');
    else if (drop.passwordProtected) toast.success('Link copied. Share the password separately.');
    else toast.success('Link copied. The key after # stays on your device.');
  };

  const changeFilter = (value: string) => {
    if (!isFilter(value)) return;
    setStatus(value);
    setPage(1);
  };

  const deleting = toDelete ? nameOf(toDelete.id) : null;
  const deleteName = deleting?.kind === 'ready' ? deleting.names.join(', ') : null;
  const returnPath = `${location.pathname}${location.search}`;
  const empty = drops.isSuccess && drops.data.total === 0;
  const empties = EMPTY_COPY[status];

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Your drops, decrypted locally with your account key. The server only ever sees encrypted names."
        actions={
          <ButtonLink to="/" icon={FilePlus2}>
            New drop
          </ButtonLink>
        }
      />

      <div className="flex flex-col gap-6">
        {user ? (
          <StorageMeter usedBytes={user.storageUsedBytes} quotaBytes={user.storageQuotaBytes} />
        ) : null}

        {accountKey === null ? (
          <Alert
            tone="info"
            title="Your vault is locked"
            action={
              <ButtonLink to={unlockPath(returnPath)} size="sm" icon={LockKeyhole}>
                Unlock
              </ButtonLink>
            }
          >
            File names stay encrypted until you unlock. Sending, deleting and password-drop links
            keep working.
          </Alert>
        ) : null}

        <Card as="section" aria-labelledby="drops-title">
          <div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
            <h2 id="drops-title" className="text-base font-semibold tracking-tight text-foreground">
              Your drops
            </h2>
            <Tabs value={status} onValueChange={changeFilter} variant="pills">
              <TabsList aria-label="Filter drops">
                {FILTERS.map((f) => (
                  <TabsTrigger key={f.value} value={f.value}>
                    {f.label}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>

          {drops.isPending ? (
            <ListSkeleton />
          ) : drops.isError ? (
            <ErrorState
              title="Couldn't load your drops"
              error={drops.error}
              onRetry={() => void drops.refetch()}
              retrying={drops.isFetching}
            />
          ) : empty ? (
            <EmptyState
              icon={LayoutDashboard}
              title={empties.title}
              description={empties.description}
              action={
                <ButtonLink to="/" icon={FilePlus2}>
                  Send a drop
                </ButtonLink>
              }
            />
          ) : (
            <ul
              className="divide-y divide-border"
              aria-label="Drops"
              aria-busy={drops.isPlaceholderData}
            >
              {items.map((drop) => (
                <DropRow
                  key={drop.id}
                  drop={drop}
                  names={nameOf(drop.id)}
                  onCopy={(d) => void onCopy(d)}
                  onDelete={setToDelete}
                />
              ))}
            </ul>
          )}

          {drops.isSuccess && drops.data.total > 0 ? (
            <div className="border-t border-border p-4 sm:p-5">
              <Pagination
                page={page}
                pageSize={PAGE_SIZE}
                total={drops.data.total}
                onPageChange={setPage}
                label="Drop pages"
              />
            </div>
          ) : null}
        </Card>
      </div>

      <ConfirmDialog
        open={toDelete !== null}
        onOpenChange={(open) => {
          if (!open) setToDelete(null);
        }}
        tone="danger"
        title="Delete this drop?"
        description="The encrypted files are deleted from the server now and the link stops working for everyone. This cannot be undone."
        confirmLabel="Delete drop"
        onConfirm={async () => {
          if (toDelete) await remove.mutateAsync(toDelete.id);
        }}
      >
        {deleteName ? (
          <p
            dir="auto"
            className="truncate rounded-lg bg-surface-2 px-3 py-2 text-sm font-medium text-foreground"
          >
            {deleteName}
          </p>
        ) : null}
      </ConfirmDialog>
    </>
  );
}
