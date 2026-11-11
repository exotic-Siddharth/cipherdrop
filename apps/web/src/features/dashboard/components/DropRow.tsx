import type { OwnerDropSummary } from '@cipherdrop/shared';
import { FileLock2, Link2, Lock, LockKeyhole, Trash2, TriangleAlert } from 'lucide-react';
import { Badge } from '../../../components/ui/Badge';
import { Button } from '../../../components/ui/Button';
import { Skeleton } from '../../../components/ui/Skeleton';
import { formatBytes, formatDate, formatRelative, pluralize } from '../../../lib/format';
import type { DropNameState } from '../useOwnerDropNames';
import { ExpiryBadge } from './ExpiryBadge';
import { StatusBadge } from './StatusBadge';

export interface DropRowProps {
  drop: OwnerDropSummary;
  names: DropNameState;
  onCopy: (drop: OwnerDropSummary) => void;
  onDelete: (drop: OwnerDropSummary) => void;
}

function NameBlock({ drop, names }: Pick<DropRowProps, 'drop' | 'names'>) {
  if (names.kind === 'ready') {
    const [first, ...rest] = names.names;
    return (
      <>
        <p className="flex min-w-0 items-center gap-2">
          <span
            dir="auto"
            className="truncate font-medium text-foreground"
            title={names.names.join('\n')}
          >
            {first}
          </span>
          {rest.length > 0 ? (
            <Badge tone="outline" className="shrink-0">
              +{rest.length} more
            </Badge>
          ) : null}
        </p>
        {names.note ? (
          <p dir="auto" className="mt-0.5 truncate text-sm text-muted-strong" title={names.note}>
            {names.note}
          </p>
        ) : null}
      </>
    );
  }
  if (names.kind === 'pending') {
    return (
      <div role="status" aria-label="Decrypting file names" className="py-1">
        <Skeleton className="h-4 w-40 max-w-full" />
      </div>
    );
  }
  if (names.kind === 'locked') {
    return (
      <p className="flex items-center gap-2 font-medium text-muted-strong">
        <Lock className="size-4 shrink-0" aria-hidden="true" />
        Locked
        <span className="sr-only"> (unlock your vault to see file names)</span>
      </p>
    );
  }
  const label = names.kind === 'error' ? "Couldn't decrypt names" : 'Name unavailable';
  const hint =
    names.kind === 'error'
      ? 'The stored key or manifest did not decrypt.'
      : 'Created while your vault was locked, so its name cannot be shown.';
  return (
    <>
      <p className="flex items-center gap-2 font-medium text-muted-strong">
        {names.kind === 'error' ? (
          <TriangleAlert className="size-4 shrink-0 text-warning-ink" aria-hidden="true" />
        ) : (
          <FileLock2 className="size-4 shrink-0" aria-hidden="true" />
        )}
        {label}
      </p>
      <p className="mt-0.5 text-sm text-muted-strong">
        {hint} {pluralize(drop.fileCount, 'file')}.
      </p>
    </>
  );
}

/** One drop of the owner's list: decrypted name (or a locked state), status, downloads, expiry and actions. */
export function DropRow({ drop, names, onCopy, onDelete }: DropRowProps) {
  // The server flips READY to EXPIRED in a cleanup pass (every minute); until then the clock decides.
  const status =
    drop.status === 'READY' && new Date(drop.expiresAt).getTime() <= Date.now()
      ? 'EXPIRED'
      : drop.status;
  const live = status === 'READY' || status === 'UPLOADING';
  const locked = names.kind === 'locked';
  // A password drop's link carries no key, so it can be copied even while the vault is locked.
  const copyDisabled =
    !live ||
    (!drop.passwordProtected && (locked || names.kind === 'unavailable')) ||
    names.kind === 'pending' ||
    (names.kind === 'error' && !drop.passwordProtected);
  const copyHint = !live
    ? 'This drop is no longer shareable'
    : names.kind === 'unavailable' && !drop.passwordProtected
      ? 'The key was not saved with this drop'
      : locked && !drop.passwordProtected
        ? 'Unlock your vault to rebuild the link'
        : undefined;

  return (
    <li className="grid gap-x-4 gap-y-3 p-4 sm:p-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1.4fr)_auto] lg:items-center">
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary-ink">
          {locked ? (
            <LockKeyhole className="size-[18px]" aria-hidden="true" />
          ) : (
            <FileLock2 className="size-[18px]" aria-hidden="true" />
          )}
        </span>
        <div className="min-w-0">
          <NameBlock drop={drop} names={names} />
          <p className="mt-1 text-xs text-muted-strong">
            {pluralize(drop.fileCount, 'file')} · {formatBytes(drop.totalBytes)}
            {drop.passwordProtected ? (
              <>
                {' · '}
                <span className="inline-flex items-center gap-1">
                  <Lock className="size-3" aria-hidden="true" />
                  Password
                </span>
              </>
            ) : null}
          </p>
        </div>
      </div>

      <dl className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <div className="flex items-center gap-2">
          <dt className="sr-only">Status</dt>
          <dd>
            <StatusBadge status={status} />
          </dd>
        </div>
        <div className="flex items-center gap-1.5">
          <dt className="text-muted-strong">Downloads</dt>
          <dd className="font-medium tabular-nums text-foreground">
            {drop.downloadCount}/{drop.maxDownloads}
          </dd>
        </div>
        {live || new Date(drop.expiresAt).getTime() <= Date.now() ? (
          <div className="flex items-center gap-1.5">
            <dt className="sr-only">Expiry</dt>
            <dd>
              <ExpiryBadge expiresAt={drop.expiresAt} status={status} />
            </dd>
          </div>
        ) : null}
        <div className="flex items-center gap-1.5 text-muted-strong">
          <dt className="sr-only">Created</dt>
          <dd title={formatDate(drop.createdAt)}>Created {formatRelative(drop.createdAt)}</dd>
        </div>
      </dl>

      <div className="flex items-center gap-2 lg:justify-end">
        <Button
          variant="outline"
          size="sm"
          icon={Link2}
          disabled={copyDisabled}
          title={copyHint}
          onClick={() => onCopy(drop)}
          aria-label={`Copy link for ${names.kind === 'ready' ? (names.names[0] ?? 'drop') : 'drop'} ${drop.id}`}
        >
          Copy link
        </Button>
        <Button
          variant="ghost"
          size="sm"
          icon={Trash2}
          className="text-danger-ink hover:bg-danger/10"
          onClick={() => onDelete(drop)}
          aria-label={`Delete drop ${drop.id}`}
        >
          Delete
        </Button>
      </div>
    </li>
  );
}
