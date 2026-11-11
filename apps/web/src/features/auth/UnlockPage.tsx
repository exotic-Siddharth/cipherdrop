import { VaultSchema } from '@cipherdrop/shared';
import { useQuery } from '@tanstack/react-query';
import { LockKeyhole, LogOut, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate, useSearchParams } from 'react-router';
import { PageHeader } from '../../components/layout/PageHeader';
import { useSignOut } from '../../components/layout/useSignOut';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardContent } from '../../components/ui/Card';
import { ErrorState } from '../../components/ui/EmptyState';
import { PasswordInput } from '../../components/ui/PasswordInput';
import { ProgressBar } from '../../components/ui/ProgressBar';
import { SkeletonText } from '../../components/ui/Skeleton';
import { api } from '../../lib/api';
import { safeNextPath } from '../../lib/paths';
import { queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { useVault } from '../../stores/vault';
import { accountErrorMessage } from '../account/accountErrors';
import { useAccountActions } from '../account/useAccountActions';

export function Component() {
  const actions = useAccountActions();
  const signOut = useSignOut();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeNextPath(params.get('next'));
  const email = useAuth((s) => s.user?.email);
  const unlocked = useVault((s) => s.accountKey !== null);

  const vault = useQuery({
    queryKey: queryKeys.vault(),
    queryFn: () => api.get('/auth/vault', { schema: VaultSchema }),
  });

  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);

  if (unlocked && !busy) return <Navigate to={next} replace />;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (!password) {
      setError('Enter your password.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await actions.unlock(password);
      setPassword('');
      void navigate(next, { replace: true });
    } catch (err) {
      setError(accountErrorMessage(err, 'unlock'));
      setAttempt((n) => n + 1);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Unlock vault"
        description="Enter your password to unlock your account key on this device. Nothing is sent to the server."
        icon={LockKeyhole}
      />
      {vault.isError ? (
        <ErrorState
          title="We could not load your vault"
          error={vault.error}
          onRetry={() => void vault.refetch()}
          retrying={vault.isFetching}
        />
      ) : (
        <div key={attempt} className={error ? 'motion-safe:animate-shake' : undefined}>
          <Card>
            <CardContent>
              {vault.isPending ? (
                <div aria-busy="true" aria-label="Loading your vault">
                  <SkeletonText lines={3} />
                </div>
              ) : (
                <form onSubmit={(e) => void onSubmit(e)} noValidate className="flex flex-col gap-5">
                  {email ? (
                    <p className="flex items-center gap-2 rounded-lg bg-surface-2 px-3 py-2 text-sm text-muted">
                      <ShieldCheck className="size-4 shrink-0 text-primary" aria-hidden="true" />
                      <span className="min-w-0 truncate">
                        Signed in as <span className="font-medium text-foreground">{email}</span>
                      </span>
                    </p>
                  ) : null}
                  {error ? (
                    <Alert tone="danger" live="assertive">
                      {error}
                    </Alert>
                  ) : null}
                  <PasswordInput
                    label="Password"
                    name="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={busy}
                    autoFocus
                    required
                  />
                  {busy ? (
                    <div aria-live="polite">
                      <ProgressBar label="Unlocking locally…" indeterminate size="sm" />
                    </div>
                  ) : null}
                  <Button type="submit" size="lg" icon={LockKeyhole} loading={busy} fullWidth>
                    Unlock
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </div>
      )}
      <div className="mt-6 flex justify-center">
        <Button variant="ghost" icon={LogOut} onClick={() => void signOut()}>
          Sign out
        </Button>
      </div>
    </div>
  );
}
