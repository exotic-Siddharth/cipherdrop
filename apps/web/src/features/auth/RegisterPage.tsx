import { LockKeyhole, Mail, ShieldCheck } from 'lucide-react';
import { useId, useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { PageHeader } from '../../components/layout/PageHeader';
import { PasswordStrength } from '../../components/PasswordStrength';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardContent } from '../../components/ui/Card';
import { Input } from '../../components/ui/Input';
import { PasswordInput } from '../../components/ui/PasswordInput';
import { ProgressBar } from '../../components/ui/ProgressBar';
import type { StrengthScore } from '../../lib/passwordStrength';
import { safeNextPath } from '../../lib/paths';
import { accountErrorMessage } from '../account/accountErrors';
import { RecoveryKeyCard } from '../account/RecoveryKeyCard';
import { useAccountActions } from '../account/useAccountActions';
import { MIN_NEW_PASSWORD_LENGTH, validateNewPassword } from './passwordRules';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function Component() {
  const actions = useAccountActions();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeNextPath(params.get('next'));
  const strengthId = useId();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [score, setScore] = useState<StrengthScore | null>(null);
  const [errors, setErrors] = useState<{ email?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);

  if (recoveryKey) {
    return (
      <div className="mx-auto max-w-lg">
        <PageHeader
          title="Your account is ready"
          description="One last step: keep your recovery key somewhere safe."
          icon={ShieldCheck}
        />
        <RecoveryKeyCard
          recoveryKey={recoveryKey}
          continueLabel="Continue to my files"
          onContinue={() => void navigate(next, { replace: true })}
        />
      </div>
    );
  }

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const trimmed = email.trim();
    const nextErrors: typeof errors = {};
    if (!EMAIL_RE.test(trimmed)) nextErrors.email = 'Enter a valid email address.';
    const passwordProblem = validateNewPassword(password, score);
    if (passwordProblem) nextErrors.password = passwordProblem;
    if (confirm !== password) nextErrors.confirm = 'The two passwords do not match.';
    setErrors(nextErrors);
    setFormError(null);
    if (Object.keys(nextErrors).length > 0) return;

    setBusy(true);
    try {
      const result = await actions.register(trimmed, password);
      setPassword('');
      setConfirm('');
      setRecoveryKey(result.recoveryKey);
    } catch (err) {
      setFormError(accountErrorMessage(err, 'register'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Create your account"
        description="Your password never leaves this device. We cannot read your files, and we cannot reset your password."
      />
      <Card>
        <CardContent>
          <form onSubmit={(e) => void onSubmit(e)} noValidate className="flex flex-col gap-5">
            {formError ? (
              <Alert tone="danger" live="assertive">
                {formError}
              </Alert>
            ) : null}
            <Input
              label="Email"
              type="email"
              name="email"
              autoComplete="email"
              inputMode="email"
              leadingIcon={Mail}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              error={errors.email}
              disabled={busy}
              required
            />
            <div className="flex flex-col gap-3">
              <PasswordInput
                label="Password"
                name="new-password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                error={errors.password}
                aria-describedby={strengthId}
                disabled={busy}
                hint={`At least ${MIN_NEW_PASSWORD_LENGTH} characters. A few random words work well.`}
                required
              />
              <PasswordStrength
                id={strengthId}
                password={password}
                userInputs={email ? [email, email.split('@')[0] ?? ''] : []}
                onScoreChange={setScore}
              />
            </div>
            <PasswordInput
              label="Confirm password"
              name="confirm-password"
              autoComplete="new-password"
              showIcon={false}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              error={errors.confirm}
              disabled={busy}
              required
            />

            {busy ? (
              <div aria-live="polite">
                <ProgressBar label="Deriving keys locally…" indeterminate size="sm" />
                <p className="mt-2 text-xs text-muted-strong">
                  Your browser is turning the password into encryption keys. This takes a moment on
                  purpose.
                </p>
              </div>
            ) : null}

            <Button type="submit" size="lg" icon={LockKeyhole} loading={busy} fullWidth>
              Create account
            </Button>
          </form>
        </CardContent>
      </Card>
      <p className="mt-6 text-center text-sm text-muted-strong">
        Already have an account?{' '}
        <Link
          to={next === '/dashboard' ? '/login' : `/login?next=${encodeURIComponent(next)}`}
          className="font-medium text-primary-ink underline-offset-4 hover:underline"
        >
          Log in
        </Link>
      </p>
    </div>
  );
}
