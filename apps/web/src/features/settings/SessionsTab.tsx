import { SessionListResponseSchema, type SessionInfo } from '@cipherdrop/shared';
import { useQuery } from '@tanstack/react-query';
import { Laptop, LogOut, MonitorX, Smartphone, Tablet } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { EmptyState, ErrorState } from '../../components/ui/EmptyState';
import { Skeleton } from '../../components/ui/Skeleton';
import { api } from '../../lib/api';
import { formatDate, formatRelative } from '../../lib/format';
import { queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { useAccountActions } from '../account/useAccountActions';
import { ReauthDialog } from './ReauthDialog';

function deviceIcon(userAgent: string | null) {
  const ua = userAgent?.toLowerCase() ?? '';
  if (/ipad|tablet/.test(ua)) return Tablet;
  if (/android|iphone|ios|mobile/.test(ua)) return Smartphone;
  return Laptop;
}

function SessionRow({ session, onRevoke }: { session: SessionInfo; onRevoke: () => void }) {
  const Icon = deviceIcon(session.userAgent);
  return (
    <li className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
          <Icon className="size-5" aria-hidden="true" />
        </span>
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-foreground">
            <span className="min-w-0 truncate">{session.userAgent ?? 'Unknown device'}</span>
            {session.current ? (
              <Badge tone="primary" dot>
                This device
              </Badge>
            ) : null}
          </p>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-strong">
            {session.ipPrefix ? (
              <span className="font-mono">{session.ipPrefix}</span>
            ) : (
              'Unknown network'
            )}
            {' · '}
            Active{' '}
            <time dateTime={session.lastUsedAt} title={formatDate(session.lastUsedAt)}>
              {formatRelative(session.lastUsedAt)}
            </time>
            {' · '}
            Signed in{' '}
            <time dateTime={session.createdAt} title={formatDate(session.createdAt)}>
              {formatRelative(session.createdAt)}
            </time>
          </p>
        </div>
      </div>
      {session.current ? null : (
        <Button
          variant="outline"
          size="sm"
          icon={MonitorX}
          onClick={onRevoke}
          aria-label={`Sign out ${session.userAgent ?? 'unknown device'}`}
        >
          Sign out
        </Button>
      )}
    </li>
  );
}

/**
 * Spec 11.2 Sessions tab: list with the current badge, revoke one, revoke all others. Signing a session out asks
 * for the password (and the 2FA code when it is on), like every sensitive action: a stolen session alone cannot
 * sign the owner's devices out.
 */
export function SessionsTab() {
  const actions = useAccountActions();
  const totpEnabled = useAuth((s) => s.user?.totpEnabled ?? false);
  const sessions = useQuery({
    queryKey: queryKeys.sessions(),
    queryFn: () => api.get('/auth/sessions', { schema: SessionListResponseSchema }),
  });
  const [revoking, setRevoking] = useState<SessionInfo | null>(null);
  const [confirmOthers, setConfirmOthers] = useState(false);

  const list = sessions.data ?? [];
  const others = list.filter((s) => !s.current);

  return (
    <>
      <Card as="section" aria-labelledby="sessions-title">
        <CardHeader
          title={<span id="sessions-title">Where you are signed in</span>}
          description="Devices and browsers with an active session. Sign out any you do not recognise."
          actions={
            others.length > 0 ? (
              <Button
                variant="outline"
                size="sm"
                icon={LogOut}
                onClick={() => setConfirmOthers(true)}
              >
                Sign out all others
              </Button>
            ) : null
          }
        />
        <CardContent className="pt-5">
          {sessions.isPending ? (
            <div className="flex flex-col gap-4" aria-busy="true" aria-label="Loading sessions">
              {[0, 1].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : sessions.isError ? (
            <ErrorState
              title="We could not load your sessions"
              error={sessions.error}
              onRetry={() => void sessions.refetch()}
              retrying={sessions.isFetching}
            />
          ) : list.length === 0 ? (
            <EmptyState icon={Laptop} size="sm" title="No active sessions" />
          ) : (
            <ul className="divide-y divide-border">
              {list.map((s) => (
                <SessionRow key={s.id} session={s} onRevoke={() => setRevoking(s)} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <ReauthDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title="Sign out this session?"
        description={`${revoking?.userAgent ?? 'That device'} will be signed out right away. Enter your password to confirm.`}
        confirmLabel="Sign out"
        tone="danger"
        password
        code={totpEnabled ? 'mfa' : false}
        busyHint="Checking your password locally…"
        onSubmit={async ({ password, code }) => {
          if (!revoking) return;
          await actions.revokeSession(revoking.id, password, totpEnabled ? code : undefined);
          toast.success('Session signed out');
        }}
      />
      <ReauthDialog
        open={confirmOthers}
        onOpenChange={setConfirmOthers}
        title="Sign out of all other devices?"
        description="Every session except this one is ended immediately. You stay signed in here. Enter your password to confirm."
        confirmLabel="Sign out all others"
        tone="danger"
        password
        code={totpEnabled ? 'mfa' : false}
        busyHint="Checking your password locally…"
        onSubmit={async ({ password, code }) => {
          await actions.revokeOtherSessions(password, totpEnabled ? code : undefined);
          toast.success('Signed out of all other devices');
        }}
      />
    </>
  );
}
