import { CircleCheck, Download, ListChecks } from 'lucide-react';
import { useState } from 'react';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Checkbox } from '../../components/ui/Checkbox';
import { CopyButton } from '../../components/ui/CopyField';
import { saveTextFile } from '../../lib/files';
import { BACKUP_CODES_FILE_NAME, backupCodesFileText } from '../account/textFiles';

export interface BackupCodesPanelProps {
  codes: readonly string[];
  onDone: () => void;
}

/** The one-time view of the backup codes: copy, download, and a gate before leaving. */
export function BackupCodesPanel({ codes, onDone }: BackupCodesPanelProps) {
  const [saved, setSaved] = useState(false);
  return (
    <div className="flex flex-col gap-4">
      <Alert tone="warning" title="Save these backup codes now" live="polite">
        They are shown only once. Each code can replace an authenticator code one time, for example
        if you lose your phone.
      </Alert>
      <ul
        aria-label="Backup codes"
        className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-lg border border-border-strong bg-surface-2 p-4 font-mono text-sm font-medium text-foreground sm:grid-cols-2"
      >
        {codes.map((code) => (
          <li key={code} className="select-all tracking-wide">
            {code}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <CopyButton value={codes.join('\n')} label="Copy codes" />
        <Button
          variant="outline"
          icon={Download}
          onClick={() => saveTextFile(backupCodesFileText(codes), BACKUP_CODES_FILE_NAME)}
        >
          Download .txt
        </Button>
      </div>
      <Checkbox
        label="I saved my backup codes"
        checked={saved}
        onChange={(e) => setSaved(e.target.checked)}
      />
      <div>
        <Button icon={saved ? CircleCheck : ListChecks} disabled={!saved} onClick={onDone}>
          Done
        </Button>
      </div>
    </div>
  );
}
