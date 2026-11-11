import { CheckCircle2, Loader2, RotateCw, X } from 'lucide-react';
import { Badge, Button, Card, CardContent, CardHeader, ProgressBar } from '../../../components/ui';
import { formatBytes, formatDuration, formatPercent, formatThroughput } from '../../../lib/format';
import type { SendPhase } from '../sendFlow';
import { FileList } from './FileList';
import { HexStream } from './HexStream';

export interface FileProgress {
  id: string;
  name: string;
  size: number;
  type: string;
  encrypted: number;
  uploaded: number;
  done: boolean;
}

export interface UploadProgressProps {
  phase: SendPhase;
  files: readonly FileProgress[];
  /** Bytes per second over the last few seconds, or null before there is a sample. */
  speed: number | null;
  hex: string | null;
  retryNotice: string | null;
  onCancel: () => void;
  cancelling: boolean;
}

const PHASE_TEXT: Record<SendPhase, string> = {
  preparing: 'Generating keys and encrypting the file list...',
  deriving: 'Deriving the password key locally (this takes a few seconds)...',
  creating: 'Creating the drop...',
  checking: 'Checking what the server already has...',
  uploading: 'Encrypting and uploading...',
  completing: 'Finishing up...',
};

function fileState(f: FileProgress): { label: string; tone: 'neutral' | 'primary' | 'success' } {
  if (f.done) return { label: 'Done', tone: 'success' };
  if (f.uploaded > 0 || f.encrypted > 0)
    return f.encrypted > f.uploaded
      ? { label: 'Uploading', tone: 'primary' }
      : { label: 'Encrypting', tone: 'primary' };
  return { label: 'Waiting', tone: 'neutral' };
}

export function UploadProgress({
  phase,
  files,
  speed,
  hex,
  retryNotice,
  onCancel,
  cancelling,
}: UploadProgressProps) {
  const total = files.reduce((n, f) => n + f.size, 0);
  const uploaded = files.reduce((n, f) => n + Math.min(f.size, f.uploaded), 0);
  const allDone = files.length > 0 && files.every((f) => f.done);
  const ratio = total > 0 ? uploaded / total : allDone ? 1 : 0;
  const eta = speed && speed > 0 && total > uploaded ? ((total - uploaded) / speed) * 1000 : null;
  const busyBeforeUpload =
    phase === 'preparing' || phase === 'deriving' || phase === 'creating' || phase === 'checking';

  return (
    <Card>
      <CardHeader
        title="Encrypting and uploading"
        description="Files are encrypted in your browser before a single byte is sent."
        actions={
          <Button variant="outline" size="sm" icon={X} onClick={onCancel} loading={cancelling}>
            Cancel
          </Button>
        }
      />
      <CardContent className="space-y-5">
        <div className="space-y-2">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            {/* Only the phase is announced: the byte counts change every chunk, and the progressbar has its own value. */}
            <p
              aria-live="polite"
              className="flex items-center gap-2 text-sm font-medium text-foreground"
            >
              <Loader2
                className="size-4 animate-spin text-primary motion-reduce:animate-none"
                aria-hidden="true"
              />
              {PHASE_TEXT[phase]}
            </p>
            <p className="text-sm text-muted tabular-nums">
              {formatBytes(uploaded)} of {formatBytes(total)}
              {speed ? ` · ${formatThroughput(speed)}` : ''}
              {eta !== null ? ` · ${formatDuration(eta)} left` : ''}
            </p>
          </div>
          <ProgressBar
            label="Overall progress"
            hideLabel
            value={ratio * 100}
            indeterminate={busyBeforeUpload}
            valueText={busyBeforeUpload ? PHASE_TEXT[phase] : formatPercent(ratio)}
            size="lg"
          />
          <p className="text-right text-xs font-medium text-muted tabular-nums" aria-hidden="true">
            {busyBeforeUpload ? '' : formatPercent(ratio)}
          </p>
        </div>

        {retryNotice ? (
          <p
            className="flex items-center gap-2 rounded-md bg-warning/10 px-3 py-2 text-sm text-warning-ink"
            role="status"
          >
            <RotateCw className="size-4 shrink-0" aria-hidden="true" />
            {retryNotice}
          </p>
        ) : null}

        <HexStream hex={hex} active={phase === 'uploading'} />

        {files.length > 0 ? (
          <FileList
            label="Upload progress per file"
            items={files.map((f) => {
              const s = fileState(f);
              const encPct = f.size > 0 ? f.encrypted / f.size : f.encrypted > 0 || f.done ? 1 : 0;
              const upPct = f.size > 0 ? f.uploaded / f.size : f.done ? 1 : 0;
              return {
                key: f.id,
                name: f.name,
                size: f.size,
                type: f.type,
                trailing: (
                  <Badge tone={s.tone} icon={f.done ? CheckCircle2 : undefined} size="sm">
                    {s.label}
                  </Badge>
                ),
                detail: (
                  <div className="space-y-1">
                    <ProgressBar
                      label={`Upload progress of ${f.name}`}
                      hideLabel
                      value={upPct * 100}
                      size="sm"
                      tone={f.done ? 'success' : 'primary'}
                    />
                    <p className="text-xs text-muted tabular-nums">
                      Encrypted {formatPercent(Math.min(1, encPct))} · Uploaded{' '}
                      {formatPercent(Math.min(1, upPct))}
                    </p>
                  </div>
                ),
              };
            })}
          />
        ) : null}
      </CardContent>
    </Card>
  );
}
