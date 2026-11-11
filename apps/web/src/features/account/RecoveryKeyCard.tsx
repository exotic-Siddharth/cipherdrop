import { ArrowRight, Download, KeyRound, TriangleAlert } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { Checkbox } from '../../components/ui/Checkbox';
import { CopyButton } from '../../components/ui/CopyField';
import { saveTextFile } from '../../lib/files';
import { RECOVERY_FILE_NAME, recoveryKeyFileText } from './textFiles';

export interface RecoveryKeyCardProps {
  /** The formatted key (XXXX-XXXX-... 8 groups of 4). It is shown once and never stored by the app. */
  recoveryKey: string;
  /** Called when the user confirms they saved it and clicks Continue. */
  onContinue: () => void;
  continueLabel?: string;
  title?: ReactNode;
  description?: ReactNode;
  className?: string;
}

/**
 * The recovery-key step shared by /register, /recover and recovery-key rotation (spec 11.2): the key in
 * monospace groups, Copy, Download .txt, and Continue disabled until "I saved my recovery key" is checked.
 */
export function RecoveryKeyCard({
  recoveryKey,
  onContinue,
  continueLabel = 'Continue',
  title = 'Save your recovery key',
  description = 'If you forget your password, this key is the only way back into your account and your files.',
  className,
}: RecoveryKeyCardProps) {
  const [saved, setSaved] = useState(false);

  // Reloading or closing the tab before the key is saved loses it for good: ask first.
  useEffect(() => {
    if (saved) return undefined;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [saved]);

  const rows = [recoveryKey.slice(0, 19), recoveryKey.slice(20)];

  return (
    <Card className={className}>
      <CardHeader title={title} description={description} icon={KeyRound} titleAs="h2" />
      <CardContent className="flex flex-col gap-5">
        <Alert tone="warning" icon={TriangleAlert} title="This is shown only once">
          We never see your recovery key and cannot reset your password for you. Store it somewhere
          safe, like a password manager or a printout.
        </Alert>

        <div
          role="group"
          aria-label="Your recovery key"
          className="rounded-lg border border-border-strong bg-surface-2 px-4 py-4 text-center font-mono text-base font-medium tracking-wider text-foreground select-all sm:text-lg"
        >
          {rows.map((row) => (
            <div key={row} data-testid="recovery-key-row" className="py-0.5 break-all">
              {row}
            </div>
          ))}
        </div>

        <div className="flex flex-wrap gap-2">
          <CopyButton value={recoveryKey} label="Copy key" />
          <Button
            variant="outline"
            icon={Download}
            onClick={() => saveTextFile(recoveryKeyFileText(recoveryKey), RECOVERY_FILE_NAME)}
          >
            Download .txt
          </Button>
        </div>

        <Checkbox
          label="I saved my recovery key"
          description="I understand that without it, a forgotten password means losing access to my account."
          checked={saved}
          onChange={(e) => setSaved(e.target.checked)}
        />

        <Button iconRight={ArrowRight} disabled={!saved} onClick={onContinue} fullWidth>
          {continueLabel}
        </Button>
      </CardContent>
    </Card>
  );
}
