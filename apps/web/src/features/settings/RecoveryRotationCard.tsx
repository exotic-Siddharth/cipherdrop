import { LifeBuoy, RotateCw } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { useAuth } from '../../stores/auth';
import { RecoveryKeyCard } from '../account/RecoveryKeyCard';
import { useAccountActions } from '../account/useAccountActions';
import { ReauthDialog } from './ReauthDialog';

/** R9: replace the recovery key. The old key stops working; sessions stay signed in. */
export function RecoveryRotationCard() {
  const actions = useAccountActions();
  const totpEnabled = useAuth((s) => s.user?.totpEnabled ?? false);
  const [open, setOpen] = useState(false);
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
          <Button variant="outline" icon={RotateCw} onClick={() => setOpen(true)}>
            Replace recovery key
          </Button>
        </CardContent>
      </Card>
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
