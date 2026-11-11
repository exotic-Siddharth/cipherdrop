import {
  CheckCircle2,
  Flame,
  KeyRound,
  QrCode as QrIcon,
  Send,
  Timer,
  Trash2,
  TriangleAlert,
} from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { QrCode } from '../../../components/QrCode';
import {
  Button,
  Card,
  CardContent,
  CardFooter,
  ConfirmDialog,
  CopyField,
} from '../../../components/ui';
import { formatBytes, formatDate, formatRelative, pluralize } from '../../../lib/format';
import { cn } from '../../../lib/cn';

export interface SuccessCardProps {
  link: string;
  fileCount: number;
  totalBytes: number;
  expiresAt: string;
  maxDownloads: number;
  passwordProtected: boolean;
  onDelete: () => Promise<void>;
  onSendAnother: () => void;
}

/** spec 11.2 success card: link + QR, summary, the fragment warning, Delete now, Send another. */
export function SuccessCard({
  link,
  fileCount,
  totalBytes,
  expiresAt,
  maxDownloads,
  passwordProtected,
  onDelete,
  onSendAnother,
}: SuccessCardProps) {
  const [showQr, setShowQr] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const summary = [
    {
      icon: Timer,
      label: 'Expires',
      value: formatRelative(expiresAt),
      title: formatDate(expiresAt),
    },
    {
      icon: Flame,
      label: 'Downloads',
      value: maxDownloads === 1 ? '1 (burn after reading)' : String(maxDownloads),
    },
    { icon: KeyRound, label: 'Password', value: passwordProtected ? 'Yes' : 'No' },
  ];

  return (
    <Card className="animate-pop-in">
      <CardContent className="space-y-5 pt-6">
        <div className="flex items-start gap-3" role="status">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-full bg-success/10 text-success-ink">
            <CheckCircle2 className="size-5" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-foreground">Your encrypted link is ready</h2>
            <p className="text-sm text-muted">
              {pluralize(fileCount, 'file')} · {formatBytes(totalBytes)}, encrypted end to end.
            </p>
          </div>
        </div>

        <CopyField
          label="Share link"
          value={link}
          copyLabel="Copy link"
          onCopied={() => toast.success('Link copied')}
        />

        <div
          className={cn(
            'flex items-start gap-2 rounded-lg px-3 py-2.5 text-sm',
            'bg-warning/10 text-warning-ink',
          )}
        >
          <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <p>
            {passwordProtected
              ? 'This link has no key in it: recipients need the password. Send the password through a different channel than the link.'
              : 'The key after # never reaches our server. Anyone with the full link can download.'}
          </p>
        </div>

        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {summary.map(({ icon: Icon, label, value, title }) => (
            <div
              key={label}
              className="flex items-center gap-2.5 rounded-lg border border-border px-3 py-2.5"
            >
              <Icon className="size-4 shrink-0 text-primary" aria-hidden="true" />
              <div className="min-w-0">
                <dt className="text-xs text-muted">{label}</dt>
                <dd className="truncate text-sm font-medium text-foreground" title={title}>
                  {value}
                </dd>
              </div>
            </div>
          ))}
        </dl>

        <div>
          <Button
            variant="ghost"
            size="sm"
            icon={QrIcon}
            aria-expanded={showQr}
            aria-controls="send-qr"
            onClick={() => setShowQr((v) => !v)}
          >
            {showQr ? 'Hide QR code' : 'Show QR code'}
          </Button>
          {showQr ? (
            <div
              id="send-qr"
              className="mt-3 flex justify-center rounded-lg border border-border bg-white p-4 sm:justify-start"
            >
              <QrCode value={link} size={192} label="QR code of the share link" />
            </div>
          ) : null}
        </div>
      </CardContent>
      <CardFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
        <Button
          variant="ghost"
          icon={Trash2}
          onClick={() => setConfirmDelete(true)}
          className="text-danger-ink"
        >
          Delete now
        </Button>
        <Button icon={Send} onClick={onSendAnother}>
          Send another
        </Button>
      </CardFooter>
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete this drop now?"
        description="The encrypted files are removed from the server right away. The link stops working for everyone."
        confirmLabel="Delete drop"
        tone="danger"
        onConfirm={onDelete}
      />
    </Card>
  );
}
