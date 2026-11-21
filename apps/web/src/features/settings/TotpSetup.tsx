import type { BackupCodesResponse, TotpSetupResponse } from '@cipherdrop/shared';
import { ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { QrCode } from '../../components/QrCode';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { CopyField } from '../../components/ui/CopyField';
import { Input } from '../../components/ui/Input';
import { PasswordInput } from '../../components/ui/PasswordInput';
import { accountErrorMessage } from '../account/accountErrors';

export interface TotpSetupProps {
  /** The pending secret returned by POST /auth/mfa/totp/setup. */
  setup: TotpSetupResponse;
  /**
   * Re-authenticates with the password and verifies the code (POST /auth/mfa/totp/enable), then resolves with the
   * backup codes. The password is only used in the browser, to derive the proof.
   */
  onVerify: (password: string, code: string) => Promise<BackupCodesResponse>;
  onEnabled: (backupCodes: string[]) => void;
  onCancel: () => void;
}

/**
 * Step 2 of enabling 2FA: scan the QR (or type the secret), then prove the app works with a 6-digit code. The
 * password is asked too: with a stolen session alone, enrolling someone else's authenticator would lock the owner
 * out of sign-in and recovery. The server then signs out every other session, since those never passed the code.
 */
export function TotpSetup({ setup, onVerify, onEnabled, onCancel }: TotpSetupProps) {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const value = code.trim();
    if (!password) {
      setError('Enter your password.');
      return;
    }
    if (!/^\d{6}$/.test(value)) {
      setError('Enter the 6-digit code shown in your authenticator app.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await onVerify(password, value);
      setPassword('');
      onEnabled(res.backupCodes);
    } catch (err) {
      setError(accountErrorMessage(err, 'totp'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <ol className="flex list-decimal flex-col gap-1.5 pl-5 text-sm leading-relaxed text-muted">
        <li>Open an authenticator app (1Password, Aegis, Google Authenticator, Authy...).</li>
        <li>Scan the QR code, or type the secret key by hand.</li>
        <li>
          Enter your password and the 6-digit code the app shows to turn two-step verification on.
          Your other devices are then signed out: they sign in again with a code.
        </li>
      </ol>

      <div className="flex flex-col items-start gap-5 sm:flex-row">
        <div className="shrink-0 rounded-xl border border-border bg-white p-1 shadow-card">
          <QrCode value={setup.otpauthUrl} size={176} label="QR code for your authenticator app" />
        </div>
        <div className="flex min-w-0 flex-1 flex-col gap-3 self-stretch">
          <CopyField
            label="Secret key"
            value={setup.secret}
            hint="Use this if you cannot scan the code. Time-based, 6 digits, SHA-1."
            copyLabel="Copy"
          />
        </div>
      </div>

      <form onSubmit={(e) => void submit(e)} noValidate className="flex flex-col gap-4">
        {error ? (
          <Alert tone="danger" live="assertive">
            {error}
          </Alert>
        ) : null}
        <PasswordInput
          label="Your password"
          name="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          containerClassName="max-w-sm"
          disabled={busy}
        />
        <Input
          label="6-digit code"
          name="totp-code"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          mono
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          containerClassName="max-w-48"
          disabled={busy}
        />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" icon={ShieldCheck} loading={busy}>
            Verify and turn on
          </Button>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}
