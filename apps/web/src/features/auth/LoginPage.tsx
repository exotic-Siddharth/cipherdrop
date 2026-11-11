import { ArrowLeft, LogIn, Mail, ShieldCheck, Sparkles } from 'lucide-react';
import { useRef, useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { PageHeader } from '../../components/layout/PageHeader';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardContent } from '../../components/ui/Card';
import { Input } from '../../components/ui/Input';
import { PasswordInput } from '../../components/ui/PasswordInput';
import { ProgressBar } from '../../components/ui/ProgressBar';
import { getDemoCredentials } from '../../lib/demo';
import { safeNextPath } from '../../lib/paths';
import { accountErrorMessage } from '../account/accountErrors';
import { useAccountActions } from '../account/useAccountActions';

type Step = 'credentials' | 'mfa';

export function Component() {
  const actions = useAccountActions();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeNextPath(params.get('next'));
  const demo = getDemoCredentials();

  const [step, setStep] = useState<Step>('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [useBackup, setUseBackup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);

  const goOn = () => void navigate(next, { replace: true });

  const onCredentials = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const trimmed = email.trim();
    if (!trimmed || !password) {
      setError('Enter your email and password.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await actions.login(trimmed, password);
      if (res.mfaRequired) {
        setPassword('');
        setStep('mfa');
        setCode('');
        // Move focus to the code field once it exists.
        setTimeout(() => codeRef.current?.focus(), 0);
      } else {
        goOn();
      }
    } catch (err) {
      setError(accountErrorMessage(err, 'login'));
    } finally {
      setBusy(false);
    }
  };

  const onMfa = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const value = code.trim();
    const valid = useBackup
      ? /^[0-9A-Za-z]{5}-?[0-9A-Za-z]{5}$/.test(value)
      : /^\d{6}$/.test(value);
    if (!valid) {
      setError(
        useBackup
          ? 'Enter a backup code like xxxxx-xxxxx.'
          : 'Enter the 6-digit code from your authenticator app.',
      );
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await actions.completeMfa(value);
      goOn();
    } catch (err) {
      setError(accountErrorMessage(err, 'mfa'));
    } finally {
      setBusy(false);
    }
  };

  const backToCredentials = () => {
    actions.cancelMfa();
    setStep('credentials');
    setCode('');
    setUseBackup(false);
    setError(null);
  };

  if (step === 'mfa') {
    return (
      <div className="mx-auto max-w-md">
        <PageHeader
          title="Two-step verification"
          description={
            useBackup
              ? 'Enter one of your backup codes. Each code works once.'
              : 'Open your authenticator app and enter the 6-digit code for CipherDrop.'
          }
          icon={ShieldCheck}
        />
        <Card>
          <CardContent>
            <form onSubmit={(e) => void onMfa(e)} noValidate className="flex flex-col gap-5">
              {error ? (
                <Alert tone="danger" live="assertive">
                  {error}
                </Alert>
              ) : null}
              <Input
                ref={codeRef}
                label={useBackup ? 'Backup code' : '6-digit code'}
                name="code"
                value={code}
                onChange={(e) =>
                  setCode(useBackup ? e.target.value : e.target.value.replace(/\D/g, ''))
                }
                inputMode={useBackup ? 'text' : 'numeric'}
                autoComplete="one-time-code"
                maxLength={useBackup ? 11 : 6}
                placeholder={useBackup ? 'xxxxx-xxxxx' : '123456'}
                mono
                className="text-center text-lg tracking-[0.3em]"
                disabled={busy}
                autoFocus
              />
              <Button type="submit" size="lg" icon={LogIn} loading={busy} fullWidth>
                Verify and log in
              </Button>
              <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <button
                  type="button"
                  className="font-medium text-primary-ink underline-offset-4 hover:underline"
                  onClick={() => {
                    setUseBackup((v) => !v);
                    setCode('');
                    setError(null);
                  }}
                >
                  {useBackup ? 'Use my authenticator app instead' : 'Use a backup code instead'}
                </button>
                <button
                  type="button"
                  className="inline-flex items-center gap-1 text-muted-strong underline-offset-4 hover:text-foreground hover:underline"
                  onClick={backToCredentials}
                >
                  <ArrowLeft className="size-3.5" aria-hidden="true" />
                  Back
                </button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-md">
      <PageHeader title="Log in" description="Your password never leaves this device." />
      <Card>
        <CardContent>
          <form onSubmit={(e) => void onCredentials(e)} noValidate className="flex flex-col gap-5">
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
            <PasswordInput
              label="Password"
              name="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
              labelAction={
                <Link
                  to="/recover"
                  className="text-xs font-medium text-primary-ink underline-offset-4 hover:underline"
                >
                  Forgot password?
                </Link>
              }
              required
            />
            {busy ? (
              <div aria-live="polite">
                <ProgressBar label="Deriving keys locally…" indeterminate size="sm" />
              </div>
            ) : null}
            <Button type="submit" size="lg" icon={LogIn} loading={busy} fullWidth>
              Log in
            </Button>
            {demo ? (
              <Button
                variant="outline"
                icon={Sparkles}
                disabled={busy}
                onClick={() => {
                  setEmail(demo.email);
                  setPassword(demo.password);
                  setError(null);
                }}
                fullWidth
              >
                Use demo account
              </Button>
            ) : null}
          </form>
        </CardContent>
      </Card>
      <p className="mt-6 text-center text-sm text-muted-strong">
        New to CipherDrop?{' '}
        <Link
          to={next === '/dashboard' ? '/register' : `/register?next=${encodeURIComponent(next)}`}
          className="font-medium text-primary-ink underline-offset-4 hover:underline"
        >
          Create an account
        </Link>
        {' · '}
        <Link
          to="/recover"
          className="font-medium text-primary-ink underline-offset-4 hover:underline"
        >
          Recover an account
        </Link>
      </p>
    </div>
  );
}
