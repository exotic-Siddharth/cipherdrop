import { KeyRound } from 'lucide-react';
import { useId, useState, type FormEvent } from 'react';
import { toast } from 'sonner';
import { PasswordStrength } from '../../components/PasswordStrength';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { PasswordInput } from '../../components/ui/PasswordInput';
import { ProgressBar } from '../../components/ui/ProgressBar';
import type { StrengthScore } from '../../lib/passwordStrength';
import { useAuth } from '../../stores/auth';
import { accountErrorMessage } from '../account/accountErrors';
import { useAccountActions } from '../account/useAccountActions';
import { MIN_NEW_PASSWORD_LENGTH, validateNewPassword } from '../auth/passwordRules';

/** Spec 7.5 password change: new salt, the same AK re-wrapped; other sessions are signed out by the server. */
export function PasswordCard() {
  const actions = useAccountActions();
  const email = useAuth((s) => s.user?.email);
  const strengthId = useId();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [score, setScore] = useState<StrengthScore | null>(null);
  const [errors, setErrors] = useState<{ current?: string; next?: string; confirm?: string }>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const nextErrors: typeof errors = {};
    if (!current) nextErrors.current = 'Enter your current password.';
    const problem = validateNewPassword(next, score);
    if (problem) nextErrors.next = problem;
    else if (next === current) nextErrors.next = 'Choose a password you have not used here.';
    if (confirm !== next) nextErrors.confirm = 'The two passwords do not match.';
    setErrors(nextErrors);
    setError(null);
    if (Object.keys(nextErrors).length > 0) return;

    setBusy(true);
    try {
      await actions.changePassword(current, next);
      setCurrent('');
      setNext('');
      setConfirm('');
      toast.success('Password changed', {
        description: 'Your other devices were signed out. Your files did not need re-encrypting.',
      });
    } catch (err) {
      setError(accountErrorMessage(err, 'password'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card as="section" aria-labelledby="password-title">
      <CardHeader
        title={<span id="password-title">Password</span>}
        description="Changing it signs out your other devices. Your files stay readable: only the key that unlocks your vault is re-wrapped."
        icon={KeyRound}
      />
      <CardContent className="pt-5">
        <form onSubmit={(e) => void submit(e)} noValidate className="flex max-w-md flex-col gap-5">
          {error ? (
            <Alert tone="danger" live="assertive">
              {error}
            </Alert>
          ) : null}
          <PasswordInput
            label="Current password"
            name="current-password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            error={errors.current}
            disabled={busy}
          />
          <div className="flex flex-col gap-3">
            <PasswordInput
              label="New password"
              name="new-password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              error={errors.next}
              aria-describedby={strengthId}
              hint={`At least ${MIN_NEW_PASSWORD_LENGTH} characters.`}
              disabled={busy}
            />
            <PasswordStrength
              id={strengthId}
              password={next}
              userInputs={email ? [email] : []}
              onScoreChange={setScore}
            />
          </div>
          <PasswordInput
            label="Confirm new password"
            name="confirm-password"
            autoComplete="new-password"
            showIcon={false}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            error={errors.confirm}
            disabled={busy}
          />
          {busy ? (
            <div aria-live="polite">
              <ProgressBar label="Deriving keys locally…" indeterminate size="sm" />
            </div>
          ) : null}
          <div>
            <Button type="submit" loading={busy}>
              Change password
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
