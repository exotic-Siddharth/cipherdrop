import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Dialog } from '../../components/ui/Dialog';
import { Input } from '../../components/ui/Input';
import { PasswordInput } from '../../components/ui/PasswordInput';
import { accountErrorMessage, type AccountErrorContext } from '../account/accountErrors';

export interface ReauthValues {
  password: string;
  code: string;
}

export interface ReauthDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  confirmLabel: string;
  tone?: 'default' | 'danger';
  /** Ask for the account password (it is only used in the browser to derive the proof for the server). */
  password?: boolean;
  /** 'totp' = a 6-digit authenticator code; 'mfa' = a 6-digit code or a backup code. false = no code field. */
  code?: false | 'totp' | 'mfa';
  /** The user must type this phrase exactly before the confirm button works (account deletion). */
  confirmPhrase?: string;
  errorContext?: AccountErrorContext;
  busyHint?: ReactNode;
  /** Runs the action. Throw to keep the dialog open with the error shown; resolve to close it. */
  onSubmit: (values: ReauthValues) => Promise<void>;
}

/** Re-authentication prompt for sensitive actions: password and/or second-factor code, optional typed phrase. */
export function ReauthDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  tone = 'default',
  password: askPassword = true,
  code: askCode = false,
  confirmPhrase,
  errorContext = 'verify',
  busyHint,
  onSubmit,
}: ReauthDialogProps) {
  const formId = useId();
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [phrase, setPhrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Start clean every time the dialog opens: nothing typed here may linger in memory or on screen.
  useEffect(() => {
    if (!open) {
      setPassword('');
      setCode('');
      setPhrase('');
      setError(null);
    }
  }, [open]);

  const phraseOk = !confirmPhrase || phrase.trim() === confirmPhrase;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || !phraseOk) return;
    if (askPassword && !password) {
      setError('Enter your password.');
      return;
    }
    const trimmed = code.trim();
    if (askCode === 'totp' && !/^\d{6}$/.test(trimmed)) {
      setError('Enter the 6-digit code from your authenticator app.');
      return;
    }
    if (askCode === 'mfa' && !/^(\d{6}|[0-9A-Za-z]{5}-?[0-9A-Za-z]{5})$/.test(trimmed)) {
      setError('Enter your 6-digit code or a backup code.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSubmit({ password, code: trimmed });
      onOpenChange(false);
    } catch (err) {
      setError(accountErrorMessage(err, errorContext));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      dismissible={!busy}
      footer={
        <>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button
            type="submit"
            form={formId}
            variant={tone === 'danger' ? 'danger' : 'primary'}
            loading={busy}
            disabled={!phraseOk}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={(e) => void submit(e)} noValidate className="flex flex-col gap-4">
        {error ? (
          <Alert tone="danger" live="assertive">
            {error}
          </Alert>
        ) : null}
        {confirmPhrase ? (
          <Input
            label={
              <>
                Type <span className="font-mono font-semibold">{confirmPhrase}</span> to confirm
              </>
            }
            name="confirm-phrase"
            autoComplete="off"
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            disabled={busy}
          />
        ) : null}
        {askPassword ? (
          <PasswordInput
            label="Your password"
            name="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
            data-autofocus={confirmPhrase ? undefined : true}
          />
        ) : null}
        {askCode ? (
          <Input
            label={askCode === 'totp' ? '6-digit code' : 'Two-factor or backup code'}
            name="code"
            autoComplete="one-time-code"
            inputMode={askCode === 'totp' ? 'numeric' : 'text'}
            maxLength={askCode === 'totp' ? 6 : 11}
            mono
            value={code}
            onChange={(e) => setCode(e.target.value)}
            disabled={busy}
            data-autofocus={askPassword ? undefined : true}
          />
        ) : null}
        {busy && busyHint ? (
          <p className="text-xs text-muted-strong" aria-live="polite">
            {busyHint}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}
