import {
  AdminUserPageSchema,
  AdminUserResponseSchema,
  type AdminUser,
  type AdminUserPatchRequest,
  type Role,
} from '@cipherdrop/shared';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Lock,
  Pencil,
  Search,
  ShieldCheck,
  Smartphone,
  UserCheck,
  UserX,
  Users,
} from 'lucide-react';
import { useEffect, useId, useState, type FormEvent } from 'react';
import { toast } from 'sonner';
import { Alert } from '../../components/ui/Alert';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { Dialog } from '../../components/ui/Dialog';
import { EmptyState, ErrorState } from '../../components/ui/EmptyState';
import { Input } from '../../components/ui/Input';
import { Pagination } from '../../components/ui/Pagination';
import { ProgressBar } from '../../components/ui/ProgressBar';
import { Select } from '../../components/ui/Select';
import { Skeleton } from '../../components/ui/Skeleton';
import { api } from '../../lib/api';
import { cn } from '../../lib/cn';
import { describeError } from '../../lib/errors';
import { formatBytes, formatDate, pluralize } from '../../lib/format';
import { useDebouncedValue } from '../../lib/hooks';
import { queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { MAX_QUOTA_GB, parseQuotaGb, quotaToGbText } from './quota';

function usePatchUser(onDone: () => void, onFailure: (message: string) => void, ok: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: AdminUserPatchRequest }) =>
      api.patch(`/admin/users/${encodeURIComponent(id)}`, patch, {
        schema: AdminUserResponseSchema,
      }),
    onSuccess: () => {
      toast.success(ok);
      void qc.invalidateQueries({ queryKey: queryKeys.adminUsers() });
      void qc.invalidateQueries({ queryKey: queryKeys.adminStats() });
      void qc.invalidateQueries({ queryKey: queryKeys.adminAudit() });
      onDone();
    },
    onError: (err) => onFailure(describeError(err)),
  });
}

/**
 * Suspend (server-6): signs the account out everywhere and refuses its sign-ins until lifted. Its drops stay;
 * take them down one by one if they are abusive. Lifting needs no reason.
 */
function SuspendDialog({ user, onClose }: { user: AdminUser; onClose: () => void }) {
  const formId = useId();
  const suspended = user.suspendedAt !== null;
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const save = usePatchUser(
    onClose,
    setFailure,
    suspended ? 'Suspension lifted' : 'Account suspended',
  );
  const reasonError = touched && !suspended && !reason.trim() ? 'Give a reason.' : undefined;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    setFailure(null);
    if (suspended) {
      save.mutate({ id: user.id, patch: { suspended: false } });
      return;
    }
    if (!reason.trim()) return;
    save.mutate({ id: user.id, patch: { suspended: true, suspendedReason: reason.trim() } });
  };

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !save.isPending) onClose();
      }}
      title={suspended ? 'Lift the suspension' : 'Suspend account'}
      description={user.email}
      dismissible={!save.isPending}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={save.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            form={formId}
            variant={suspended ? 'primary' : 'danger'}
            loading={save.isPending}
          >
            {suspended ? 'Lift suspension' : 'Suspend'}
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={submit} noValidate className="flex flex-col gap-4">
        {suspended ? (
          <p className="text-sm text-muted-strong">
            Suspended {formatDate(user.suspendedAt ?? '')}
            {user.suspendedReason ? `: ${user.suspendedReason}` : ''}. The owner can sign in again
            once it is lifted.
          </p>
        ) : (
          <>
            <p className="text-sm text-muted-strong">
              Every session of this account is signed out at once, and it cannot sign in until you
              lift the suspension. Its drops are not touched.
            </p>
            <Input
              label="Reason"
              autoComplete="off"
              maxLength={500}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              error={reasonError}
              hint={reasonError ? undefined : 'Recorded in the audit log, not shown to the owner.'}
            />
          </>
        )}
        {failure ? (
          <Alert tone="danger" live="assertive">
            {failure}
          </Alert>
        ) : null}
      </form>
    </Dialog>
  );
}

const PAGE_SIZE = 10;

const ROLE_OPTIONS = [
  { value: 'USER', label: 'User' },
  { value: 'ADMIN', label: 'Admin' },
] as const;

function isRole(value: string): value is Role {
  return value === 'USER' || value === 'ADMIN';
}

function EditUserDialog({ user, onClose }: { user: AdminUser; onClose: () => void }) {
  const selfId = useAuth((s) => s.user?.id);
  const formId = useId();
  const [role, setRole] = useState<Role>(user.role);
  // The stored quota, not the probation cap: saving the field unchanged must not store the cap for good.
  const initialQuota = quotaToGbText(user.storageQuotaBytes);
  const [quota, setQuota] = useState(initialQuota);
  const [touched, setTouched] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const save = usePatchUser(onClose, setFailure, 'User updated');

  const parsed = parseQuotaGb(quota);
  const quotaError = touched && !parsed.ok ? parsed.error : undefined;
  const isSelf = user.id === selfId;
  const roleChanged = role !== user.role;
  // Compared with the field as it opened, not with the stored bytes: quotaToGbText rounds to 0.01 GB, so a
  // quota such as 100 MiB would otherwise read as changed, and a role-only edit would also rewrite the quota
  // (and end the probation).
  const initial = parseQuotaGb(initialQuota);
  const quotaChanged = parsed.ok && (!initial.ok || parsed.bytes !== initial.bytes);
  const belowUsage = parsed.ok && parsed.bytes < user.storageUsedBytes;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    setFailure(null);
    if (!parsed.ok || (!roleChanged && !quotaChanged)) return;
    const patch: AdminUserPatchRequest = {
      ...(roleChanged ? { role } : {}),
      ...(quotaChanged ? { storageQuotaBytes: parsed.bytes } : {}),
    };
    save.mutate({ id: user.id, patch });
  };

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !save.isPending) onClose();
      }}
      title="Edit user"
      description={user.email}
      dismissible={!save.isPending}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={save.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            form={formId}
            loading={save.isPending}
            disabled={!roleChanged && !quotaChanged}
          >
            Save changes
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={submit} noValidate className="flex flex-col gap-4">
        <Select
          label="Role"
          value={role}
          onChange={(e) => {
            if (isRole(e.target.value)) setRole(e.target.value);
          }}
          options={ROLE_OPTIONS}
          disabled={isSelf}
          hint={
            isSelf
              ? 'You cannot change your own role.'
              : role === 'ADMIN'
                ? 'Admins can disable drops and edit every account.'
                : undefined
          }
        />
        {roleChanged && role === 'ADMIN' && !user.totpEnabled ? (
          <Alert tone="warning" live="off">
            This account has no two-step verification, so it cannot be an admin yet. Ask its owner
            to turn it on in Settings, Security, then try again.
          </Alert>
        ) : null}
        <Input
          label="Storage quota"
          inputMode="decimal"
          autoComplete="off"
          value={quota}
          onChange={(e) => {
            setQuota(e.target.value);
            setTouched(true);
          }}
          error={quotaError}
          trailing={<span className="text-sm text-muted-strong">GB</span>}
          hint={
            quotaError
              ? undefined
              : `Using ${formatBytes(user.storageUsedBytes)} now. Allowed: up to ${MAX_QUOTA_GB.toLocaleString('en')} GB.`
          }
        />
        {user.quotaProbationEndsAt ? (
          <Alert tone="info" live="off">
            New account: limited to {formatBytes(user.effectiveQuotaBytes)} until{' '}
            {formatDate(user.quotaProbationEndsAt)}, then this quota applies. Saving a new quota
            ends the limit at once.
          </Alert>
        ) : null}
        {belowUsage && !quotaError ? (
          <Alert tone="warning" live="off">
            This is below the current usage: the user keeps their drops but cannot upload until they
            free space.
          </Alert>
        ) : null}
        {failure ? (
          <Alert tone="danger" live="assertive">
            {failure}
          </Alert>
        ) : null}
      </form>
    </Dialog>
  );
}

/** User management (spec 10, 11.2): search, role and quota edits, suspension (server-6). */
export function UsersCard() {
  const selfId = useAuth((s) => s.user?.id);
  const [search, setSearch] = useState('');
  const debounced = useDebouncedValue(search.trim(), 300);
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<AdminUser | null>(null);
  const [suspending, setSuspending] = useState<AdminUser | null>(null);

  useEffect(() => setPage(1), [debounced]);

  const users = useQuery({
    queryKey: queryKeys.adminUsers({ page, pageSize: PAGE_SIZE, search: debounced || undefined }),
    queryFn: () =>
      api.get('/admin/users', {
        schema: AdminUserPageSchema,
        query: { page, pageSize: PAGE_SIZE, search: debounced || undefined },
      }),
    placeholderData: keepPreviousData,
  });
  const items = users.data?.items ?? [];
  const now = Date.now();

  return (
    <Card as="section" aria-labelledby="users-title">
      <CardHeader
        icon={Users}
        title={<span id="users-title">Users</span>}
        description="Change a role or a storage quota, or suspend an account. All of it is recorded in the audit log."
      />
      <div className="px-5 pt-4 sm:px-6">
        <Input
          label="Search users"
          hideLabel
          type="search"
          placeholder="Search by email"
          leadingIcon={Search}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          maxLength={254}
          containerClassName="max-w-sm"
        />
      </div>

      <div className="mt-4 border-t border-border">
        {users.isPending ? (
          <div className="space-y-3 p-5" aria-hidden="true">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : users.isError ? (
          <ErrorState
            title="Couldn't load users"
            error={users.error}
            onRetry={() => void users.refetch()}
            retrying={users.isFetching}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={Users}
            size="sm"
            title={debounced ? 'No users match' : 'No users yet'}
            description={debounced ? `Nothing matches "${debounced}".` : undefined}
          />
        ) : (
          <ul
            aria-label="Users"
            aria-busy={users.isPlaceholderData}
            className={cn('divide-y divide-border', users.isPlaceholderData && 'opacity-70')}
          >
            {items.map((u) => {
              const locked = u.lockedUntil !== null && new Date(u.lockedUntil).getTime() > now;
              return (
                <li
                  key={u.id}
                  className="grid gap-x-6 gap-y-3 p-4 sm:p-5 lg:grid-cols-[minmax(0,1.5fr)_5.5rem_minmax(0,1fr)_auto] lg:items-center"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="break-all font-medium text-foreground">{u.email}</span>
                      {u.id === selfId ? <Badge tone="outline">You</Badge> : null}
                      {u.totpEnabled ? (
                        <Badge tone="success" icon={Smartphone}>
                          2FA
                        </Badge>
                      ) : null}
                      {locked ? (
                        <Badge tone="warning" icon={Lock}>
                          Locked out
                        </Badge>
                      ) : null}
                      {u.suspendedAt ? (
                        <Badge tone="danger" icon={UserX}>
                          Suspended
                        </Badge>
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs text-muted-strong">
                      {pluralize(u.dropCount, 'drop')} · joined {formatDate(u.createdAt)}
                    </p>
                  </div>
                  <div>
                    {u.role === 'ADMIN' ? (
                      <Badge tone="primary" icon={ShieldCheck}>
                        Admin
                      </Badge>
                    ) : (
                      <Badge tone="neutral">User</Badge>
                    )}
                  </div>
                  <div className="min-w-0">
                    <ProgressBar
                      label={`Storage of ${u.email}`}
                      hideLabel
                      size="sm"
                      value={u.storageUsedBytes}
                      max={Math.max(u.effectiveQuotaBytes, 1)}
                      tone={
                        u.storageUsedBytes >= u.effectiveQuotaBytes * 0.95 ? 'danger' : 'primary'
                      }
                      valueText={`${formatBytes(u.storageUsedBytes)} of ${formatBytes(u.effectiveQuotaBytes)}`}
                    />
                    <p className="mt-1 text-xs tabular-nums text-muted-strong">
                      {formatBytes(u.storageUsedBytes)} of {formatBytes(u.effectiveQuotaBytes)} used
                    </p>
                    {u.quotaProbationEndsAt ? (
                      <p className="mt-0.5 text-xs text-muted-strong">
                        New account: limited until {formatDate(u.quotaProbationEndsAt)}, then{' '}
                        {formatBytes(u.storageQuotaBytes)}. Editing the quota ends it.
                      </p>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap gap-2 lg:justify-end">
                    <Button
                      variant="outline"
                      size="sm"
                      icon={Pencil}
                      onClick={() => setEditing(u)}
                      aria-label={`Edit ${u.email}`}
                    >
                      Edit
                    </Button>
                    {u.id !== selfId && u.role !== 'ADMIN' ? (
                      <Button
                        variant="outline"
                        size="sm"
                        icon={u.suspendedAt ? UserCheck : UserX}
                        onClick={() => setSuspending(u)}
                        aria-label={`${u.suspendedAt ? 'Lift the suspension of' : 'Suspend'} ${u.email}`}
                      >
                        {u.suspendedAt ? 'Unsuspend' : 'Suspend'}
                      </Button>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {users.isSuccess && users.data.total > 0 ? (
        <div className="border-t border-border p-4 sm:p-5">
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={users.data.total}
            onPageChange={setPage}
            label="User pages"
          />
        </div>
      ) : null}

      {editing ? (
        <EditUserDialog key={editing.id} user={editing} onClose={() => setEditing(null)} />
      ) : null}
      {suspending ? (
        <SuspendDialog key={suspending.id} user={suspending} onClose={() => setSuspending(null)} />
      ) : null}
    </Card>
  );
}
