import { KeyRound, LockKeyhole } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Button, Card, CardContent, PasswordInput } from '../../../components/ui';
import { cn } from '../../../lib/cn';

export interface PasswordPromptProps {
  /** Resolves when unlocked; rejects with a user-facing message to show. */
  onUnlock: (password: string) => Promise<void>;
  /** Wrong-password message (triggers the shake) or rate-limit message. */
  error: string | null;
  /** Increments on every wrong password, so the shake replays. */
  shakeKey: number;
  busy: boolean;
}

export function PasswordPrompt({ onUnlock, error, shakeKey, busy }: PasswordPromptProps) {
  const [password, setPassword] = useState('');
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    await onUnlock(password);
  };
  return (
    <Card className="mx-auto max-w-md">
      <CardContent className="pt-6">
        <form onSubmit={submit} className="space-y-4" aria-labelledby="receive-password-title">
          <div className="flex flex-col items-center gap-3 text-center">
            <span className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary-ink">
              <LockKeyhole className="size-6" aria-hidden="true" />
            </span>
            <div>
              <h2 id="receive-password-title" className="text-lg font-semibold text-foreground">
                This drop is password protected
              </h2>
              <p className="mt-1 text-sm text-muted">
                Enter the password the sender gave you. It is checked on this device, then the files
                are decrypted here.
              </p>
            </div>
          </div>
          <div key={shakeKey} className={cn(shakeKey > 0 && 'motion-safe:animate-shake')}>
            <PasswordInput
              label="Password"
              autoComplete="off"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              error={error ?? undefined}
            />
          </div>
          <Button
            type="submit"
            fullWidth
            size="lg"
            icon={KeyRound}
            loading={busy}
            disabled={!password}
          >
            {busy ? 'Deriving key locally...' : 'Unlock'}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
