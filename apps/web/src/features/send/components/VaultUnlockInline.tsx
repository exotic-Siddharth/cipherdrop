import { AAD, importAesKey, unwrapKey } from '@cipherdrop/crypto';
import { VaultSchema } from '@cipherdrop/shared';
import { KeyRound, Lock } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useLocation } from 'react-router';
import { Button, PasswordInput } from '../../../components/ui';
import { kdfClient } from '../../../crypto/kdfClient';
import { api } from '../../../lib/api';
import { cn } from '../../../lib/cn';
import { describeError } from '../../../lib/errors';
import { unlockPath } from '../../../lib/paths';
import { useVault } from '../../../stores/vault';

/**
 * R7: signed in with a locked vault, Send asks for the account password inline (never navigates). The
 * account key is unwrapped locally and kept only as a non-extractable CryptoKey; the raw bytes are zeroed.
 */
export function VaultUnlockInline({ className }: { className?: string }) {
  const location = useLocation();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shakeKey, setShakeKey] = useState(0);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      const vault = await api.get('/auth/vault', { schema: VaultSchema });
      const { encKey } = await kdfClient.deriveAccountKeys(password, vault.kdf);
      const raw = await unwrapKey(encKey, vault.wrappedAccountKey, AAD.WRAP_ACCOUNT);
      try {
        useVault.getState().setAccountKey(await importAesKey(raw));
      } finally {
        raw.fill(0);
      }
      setPassword('');
    } catch (err) {
      setError(describeError(err, 'Could not unlock your vault. Please try again.'));
      setShakeKey((k) => k + 1);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={submit}
      className={cn('rounded-lg border border-warning/40 bg-warning/10 p-4', className)}
      aria-labelledby="send-vault-locked-title"
    >
      <div className="flex items-start gap-3">
        <Lock className="mt-0.5 size-5 shrink-0 text-warning-ink" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p id="send-vault-locked-title" className="text-sm font-semibold text-foreground">
            Your vault is locked
          </p>
          <p className="mt-0.5 text-sm text-muted">
            Unlock it to keep this drop on your dashboard. Your password never leaves this device.
          </p>
          <div
            key={shakeKey}
            className={cn(
              'mt-3 flex flex-col gap-2 sm:flex-row sm:items-start',
              shakeKey > 0 && 'motion-safe:animate-shake',
            )}
          >
            <PasswordInput
              label="Account password"
              hideLabel
              placeholder="Account password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              error={error ?? undefined}
              containerClassName="flex-1"
            />
            <Button type="submit" icon={KeyRound} loading={busy} disabled={!password}>
              Unlock
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted">
            Or use the{' '}
            <Link
              to={unlockPath(location.pathname)}
              className="font-medium text-primary-ink underline-offset-2 hover:underline"
            >
              unlock page
            </Link>
            .
          </p>
        </div>
      </div>
    </form>
  );
}
