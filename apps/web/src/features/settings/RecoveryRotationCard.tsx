import { RecoveryVaultSchema } from '@cipherdrop/shared';
import { FlaskConical, LifeBuoy, RotateCw } from 'lucide-react';
import { useEffect, useId, useState, type FormEvent } from 'react';
import { toast } from 'sonner';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { Dialog } from '../../components/ui/Dialog';
import { Input } from '../../components/ui/Input';
import { api } from '../../lib/api';
import { describeError } from '../../lib/errors';
import { useAuth } from '../../stores/auth';
import { RecoveryKeyCard } from '../account/RecoveryKeyCard';
import { useAccountActions } from '../account/useAccountActions';
import { ReauthDialog } from './ReauthDialog';
import { checkRecoveryKey, type RecoveryKeyCheck } from './recoveryKeyCheck';

const CHECK_TEXT: Record<RecoveryKeyCheck, string> = {
  valid: 'This recovery key works. Keep it somewhere safe, away from your password.',
  wrong:
    "This is not your current recovery key. If you can't find the right one, replace it now, while you still know your password.",
  malformed: 'A recovery key has 32 characters in 8 groups of 4. Check what you typed.',
};

/**
 * "Test recovery key" (critic-5): checks a typed key in this browser and changes nothing (no server state, no
 * audit event, no rate limit spent). Only the recovery-wrapped account key is fetched.
 */
function TestRecoveryKeyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const formId = useId();
  const [key, setKey] = useState('');
  const [result, setResult] = useState<RecoveryKeyCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) {
      setKey('');
      setResult(null);
      setError(null);
    }
  }, [open]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setResult(null);
    setError(null);
    try {
      const { wrappedAccountKeyRecovery } = await api.get('/auth/vault/recovery', {
        schema: RecoveryVaultSchema,
      });
      setResult(await checkRecoveryKey(key, wrappedAccountKeyRecovery));
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title="Test your recovery key"
      description="Type your recovery key to check it. The check runs in this browser and changes nothing."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button type="submit" form={formId} loading={busy} disabled={!key.trim()}>
            Test key
          </Button>
        </>
      }
    >
      <form id={formId} onSubmit={(e) => void submit(e)} noValidate className="flex flex-col gap-4">
        <Input
          label="Recovery key"
          name="recovery-key"
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
          placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
          value={key}
          onChange={(e) => {
            setKey(e.target.value);
            setResult(null);
          }}
        />
        {result ? (
          <Alert tone={result === 'valid' ? 'success' : 'warning'} live="polite">
            {CHECK_TEXT[result]}
          </Alert>
        ) : null}
        {error ? (
          <Alert tone="danger" live="assertive">
            {error}
          </Alert>
        ) : null}
      </form>
    </Dialog>
  );
}

/** R9: replace the recovery key. The old key stops working; sessions stay signed in. */
export function RecoveryRotationCard() {
  const actions = useAccountActions();
  const totpEnabled = useAuth((s) => s.user?.totpEnabled ?? false);
  const [open, setOpen] = useState(false);
  const [testing, setTesting] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);

  if (newKey) {
    return (
      <RecoveryKeyCard
        recoveryKey={newKey}
        title="Save your new recovery key"
        description="The previous recovery key no longer works. This one is shown only once."
        continueLabel="Done"
        onContinue={() => setNewKey(null)}
      />
    );
  }

  return (
    <>
      <Card as="section" aria-labelledby="recovery-title">
        <CardHeader
          title={<span id="recovery-title">Recovery key</span>}
          description="The one thing that gets you back in if you forget your password."
          icon={LifeBuoy}
        />
        <CardContent className="flex flex-col items-start gap-4 pt-5">
          <p className="text-sm leading-relaxed text-muted">
            Lost it, or shared it by mistake? Make a new one. The old key stops working right away,
            and you stay signed in.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" icon={FlaskConical} onClick={() => setTesting(true)}>
              Test recovery key
            </Button>
            <Button variant="outline" icon={RotateCw} onClick={() => setOpen(true)}>
              Replace recovery key
            </Button>
          </div>
        </CardContent>
      </Card>
      <TestRecoveryKeyDialog open={testing} onClose={() => setTesting(false)} />
      <ReauthDialog
        open={open}
        onOpenChange={setOpen}
        title="Replace your recovery key"
        description="Enter your password to create a new recovery key. It is made on this device."
        confirmLabel="Create new key"
        password
        code={totpEnabled ? 'mfa' : false}
        errorContext="password"
        busyHint="Deriving keys locally…"
        onSubmit={async ({ password, code }) => {
          const res = await actions.rotateRecoveryKey(password, totpEnabled ? code : undefined);
          setNewKey(res.recoveryKey);
          toast.success('Recovery key replaced');
        }}
      />
    </>
  );
}
