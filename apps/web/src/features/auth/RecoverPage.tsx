import { ArrowRight, KeyRound, LifeBuoy, Mail, ShieldCheck } from 'lucide-react';
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

type Step = 'identify' | 'password' | 'done';

export function Component() {
  const actions = useAccountActions();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeNextPath(params.get('next'));
  const strengthId = useId();

  const [step, setStep] = useState<Step>('identify');
  const [email, setEmail] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [code, setCode] = useState('');
  const [score, setScore] = useState<StrengthScore | null>(null);
  const [errors, setErrors] = useState<{ password?: string; confirm?: string; code?: string }>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [newRecoveryKey, setNewRecoveryKey] = useState<string | null>(null);

  const onIdentify = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (!email.trim() || !recoveryKey.trim()) {
      setError('Enter your email and your recovery key.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await actions.startRecovery(email.trim(), recoveryKey);
      setMfaRequired(res.mfaRequired);
      setStep('password');
    } catch (err) {
      setError(accountErrorMessage(err, 'recovery-start'));
    } finally {
      setBusy(false);
    }
  };

  const onPassword = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const nextErrors: typeof errors = {};
    const problem = validateNewPassword(password, score);
    if (problem) nextErrors.password = problem;
    if (confirm !== password) nextErrors.confirm = 'The two passwords do not match.';
    if (mfaRequired && !code.trim()) nextErrors.code = 'Enter your two-factor or backup code.';
    setErrors(nextErrors);
    setError(null);
    if (Object.keys(nextErrors).length > 0) return;

    setBusy(true);
    try {
      const res = await actions.completeRecovery(password, mfaRequired ? code : undefined);
      setPassword('');
      setConfirm('');
      setRecoveryKey('');
      setNewRecoveryKey(res.newRecoveryKey);
      setStep('done');
    } catch (err) {
      setError(accountErrorMessage(err, 'recovery-complete'));
    } finally {
      setBusy(false);
    }
  };

  if (step === 'done' && newRecoveryKey) {
    return (
      <div className="mx-auto max-w-lg">
        <PageHeader
          title="Account recovered"
          description="Your password was changed and every other device was signed out."
          icon={ShieldCheck}
        />
        <RecoveryKeyCard
          recoveryKey={newRecoveryKey}
          title="Save your new recovery key"
          description="The key you just used no longer works. This replacement is the only way back in if you forget your new password."
          continueLabel="Continue to my files"
          onContinue={() => void navigate(next, { replace: true })}
        />
      </div>
    );
  }

  if (step === 'password') {
    return (
      <div className="mx-auto max-w-md">
        <PageHeader
          title="Choose a new password"
          description="Your recovery key was accepted. Pick a new password for this account."
          icon={KeyRound}
        />
        <Card>
          <CardContent>
            <form onSubmit={(e) => void onPassword(e)} noValidate className="flex flex-col gap-5">
              {error ? (
                <Alert tone="danger" live="assertive">
                  {error}
                </Alert>
              ) : null}
              <div className="flex flex-col gap-3">
                <PasswordInput
                  label="New password"
                  name="new-password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  error={errors.password}
                  aria-describedby={strengthId}
                  disabled={busy}
                  hint={`At least ${MIN_NEW_PASSWORD_LENGTH} characters.`}
                  required
                />
                <PasswordStrength
                  id={strengthId}
                  password={password}
                  userInputs={[email]}
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
                required
              />
              {mfaRequired ? (
                <Input
                  label="Two-factor or backup code"
                  name="code"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  error={errors.code}
                  hint="This account has two-step verification turned on."
                  mono
                  disabled={busy}
                  required
                />
              ) : null}
              {busy ? (
                <div aria-live="polite">
                  <ProgressBar label="Deriving keys locally…" indeterminate size="sm" />
                </div>
              ) : null}
              <Button type="submit" size="lg" icon={KeyRound} loading={busy} fullWidth>
                Set new password
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Recover your account"
        description="Forgot your password? Your recovery key gets you back in. Your files stay encrypted the whole time."
        icon={LifeBuoy}
      />
      <Card>
        <CardContent>
          <form onSubmit={(e) => void onIdentify(e)} noValidate className="flex flex-col gap-5">
            {error ? (
              <Alert tone="danger" live="assertive">
                {error}
              </Alert>
            ) : null}
            <Input
              label="Email"
              type="email"
              name="email"
              autoComplete="username"
              inputMode="email"
              leadingIcon={Mail}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={busy}
              required
            />
            <Input
              label="Recovery key"
              name="recovery-key"
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              value={recoveryKey}
              onChange={(e) => setRecoveryKey(e.target.value)}
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
              hint="32 characters in 8 groups of 4. Dashes, spaces and capitals do not matter."
              leadingIcon={KeyRound}
              mono
              disabled={busy}
              required
            />
            {busy ? (
              <div aria-live="polite">
                <ProgressBar label="Checking your recovery key locally…" indeterminate size="sm" />
              </div>
            ) : null}
            <Button type="submit" size="lg" iconRight={ArrowRight} loading={busy} fullWidth>
              Continue
            </Button>
          </form>
        </CardContent>
      </Card>
      <p className="mt-6 text-center text-sm text-muted-strong">
        Remembered it?{' '}
        <Link
          to="/login"
          className="font-medium text-primary-ink underline-offset-4 hover:underline"
        >
          Log in
        </Link>
      </p>
    </div>
  );
}
