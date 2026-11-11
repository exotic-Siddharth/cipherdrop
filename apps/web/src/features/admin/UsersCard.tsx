import {
  AdminUserPageSchema,
  AdminUserResponseSchema,
  type AdminUser,
  type AdminUserPatchRequest,
  type Role,
} from '@cipherdrop/shared';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Lock, Pencil, Search, ShieldCheck, Smartphone, Users } from 'lucide-react';
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

const PAGE_SIZE = 10;

const ROLE_OPTIONS = [
  { value: 'USER', label: 'User' },
  { value: 'ADMIN', label: 'Admin' },
] as const;

function isRole(value: string): value is Role {
  return value === 'USER' || value === 'ADMIN';
}

function EditUserDialog({ user, onClose }: { user: AdminUser; onClose: () => void }) {
  const qc = useQueryClient();
  const selfId = useAuth((s) => s.user?.id);
  const formId = useId();
  const [role, setRole] = useState<Role>(user.role);
  const [quota, setQuota] = useState(() => quotaToGbText(user.storageQuotaBytes));
  const [touched, setTouched] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: AdminUserPatchRequest }) =>
      api.patch(`/admin/users/${encodeURIComponent(id)}`, patch, {
        schema: AdminUserResponseSchema,
      }),
    onSuccess: () => {
      toast.success('User updated');
      void qc.invalidateQueries({ queryKey: queryKeys.adminUsers() });
      void qc.invalidateQueries({ queryKey: queryKeys.adminStats() });
      onClose();
    },
    onError: (err) => setFailure(describeError(err)),
  });

  const parsed = parseQuotaGb(quota);
  const quotaError = touched && !parsed.ok ? parsed.error : undefined;
  const isSelf = user.id === selfId;
  const roleChanged = role !== user.role;
  const quotaChanged = parsed.ok && parsed.bytes !== user.storageQuotaBytes;
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

/** User management (spec 10, 11.2): search, role and quota edits. */
export function UsersCard() {
  const selfId = useAuth((s) => s.user?.id);
  const [search, setSearch] = useState('');
  const debounced = useDebouncedValue(search.trim(), 300);
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<AdminUser | null>(null);

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
        description="Change a role or a storage quota. Both are recorded in the audit log."
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
                      max={Math.max(u.storageQuotaBytes, 1)}
                      tone={u.storageUsedBytes >= u.storageQuotaBytes * 0.95 ? 'danger' : 'primary'}
                      valueText={`${formatBytes(u.storageUsedBytes)} of ${formatBytes(u.storageQuotaBytes)}`}
                    />
                    <p className="mt-1 text-xs tabular-nums text-muted-strong">
                      {formatBytes(u.storageUsedBytes)} of {formatBytes(u.storageQuotaBytes)} used
                    </p>
                  </div>
                  <div className="lg:text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      icon={Pencil}
                      onClick={() => setEditing(u)}
                      aria-label={`Edit ${u.email}`}
                    >
                      Edit
                    </Button>
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
    </Card>
  );
}
