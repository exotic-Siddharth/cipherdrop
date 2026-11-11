import type { TotpSetupResponse } from '@cipherdrop/shared';
import { RefreshCw, ShieldCheck, ShieldOff, Smartphone } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { describeError } from '../../lib/errors';
import { useAuth } from '../../stores/auth';
import { useAccountActions } from '../account/useAccountActions';
import { BackupCodesPanel } from './BackupCodesPanel';
import { ReauthDialog } from './ReauthDialog';
import { TotpSetup } from './TotpSetup';

type Dialogs = 'regenerate' | 'disable' | null;

/** Spec 11.2 Security tab, part 1: TOTP setup (QR + manual secret), backup codes shown once, regenerate, disable. */
export function TwoFactorCard() {
  const actions = useAccountActions();
  const enabled = useAuth((s) => s.user?.totpEnabled ?? false);
  const [setup, setSetup] = useState<TotpSetupResponse | null>(null);
  const [starting, setStarting] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [dialog, setDialog] = useState<Dialogs>(null);

  const start = async () => {
    setStarting(true);
    try {
      setSetup(await actions.setupTotp());
    } catch (err) {
      toast.error(describeError(err));
    } finally {
      setStarting(false);
    }
  };

  let body;
  if (codes) {
    body = <BackupCodesPanel codes={codes} onDone={() => setCodes(null)} />;
  } else if (setup && !enabled) {
    body = (
      <TotpSetup
        setup={setup}
        onVerify={actions.enableTotp}
        onEnabled={(backupCodes) => {
          setSetup(null);
          setCodes(backupCodes);
          toast.success('Two-step verification is on');
        }}
        onCancel={() => setSetup(null)}
      />
    );
  } else if (enabled) {
    body = (
      <div className="flex flex-col gap-4">
        <p className="text-sm leading-relaxed text-muted">
          Logging in needs your password and a 6-digit code from your authenticator app. If you lose
          your phone, use one of your backup codes.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" icon={RefreshCw} onClick={() => setDialog('regenerate')}>
            Regenerate backup codes
          </Button>
          <Button variant="outline" icon={ShieldOff} onClick={() => setDialog('disable')}>
            Turn off
          </Button>
        </div>
      </div>
    );
  } else {
    body = (
      <div className="flex flex-col items-start gap-4">
        <p className="text-sm leading-relaxed text-muted">
          Add a second step to logging in. Even if someone learns your password, they also need the
          code from your phone.
        </p>
        <Button icon={Smartphone} loading={starting} onClick={() => void start()}>
          Set up two-step verification
        </Button>
      </div>
    );
  }

  return (
    <>
      <Card as="section" aria-labelledby="twofactor-title">
        <CardHeader
          title={<span id="twofactor-title">Two-step verification</span>}
          description="Protect your account with an authenticator app (TOTP)."
          icon={ShieldCheck}
          actions={
            <Badge tone={enabled ? 'success' : 'neutral'} dot>
              {enabled ? 'On' : 'Off'}
            </Badge>
          }
        />
        <CardContent className="pt-5">{body}</CardContent>
      </Card>

      <ReauthDialog
        open={dialog === 'regenerate'}
        onOpenChange={(open) => setDialog(open ? 'regenerate' : null)}
        title="Regenerate backup codes"
        description="Your old backup codes stop working. Enter a code from your authenticator app to continue."
        confirmLabel="Regenerate"
        password={false}
        code="totp"
        errorContext="totp"
        onSubmit={async ({ code }) => {
          setCodes((await actions.regenerateBackupCodes(code)).backupCodes);
        }}
      />
      <ReauthDialog
        open={dialog === 'disable'}
        onOpenChange={(open) => setDialog(open ? 'disable' : null)}
        title="Turn off two-step verification"
        description="Logging in will need only your password. Enter your password and a current code to confirm."
        confirmLabel="Turn off"
        tone="danger"
        password
        code="mfa"
        busyHint="Checking your password locally…"
        onSubmit={async ({ password, code }) => {
          await actions.disableTotp(password, code);
          toast.success('Two-step verification is off');
        }}
      />
    </>
  );
}
