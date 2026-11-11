import { b64urlEncode } from '@cipherdrop/crypto';
import {
  LIMITS,
  ReportResponseSchema,
  type ReportReason,
  type ReportRequest,
} from '@cipherdrop/shared';
import { Flag } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { toast } from 'sonner';
import { Alert, Button, Checkbox, Dialog, Select, Textarea } from '../../../components/ui';
import { api } from '../../../lib/api';
import { describeError } from '../../../lib/errors';

const REASONS: Array<{ value: ReportReason; label: string }> = [
  { value: 'MALWARE', label: 'Malware or a virus' },
  { value: 'PHISHING', label: 'Phishing or a scam' },
  { value: 'ILLEGAL', label: 'Illegal content' },
  { value: 'COPYRIGHT', label: 'Copyright infringement' },
  { value: 'OTHER', label: 'Something else' },
];

export interface ReportDialogProps {
  dropId: string;
  /** The drop key, when this page knows it; sent only if the reporter opts in (R13). */
  dk: Uint8Array | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ReportDialog({ dropId, dk, open, onOpenChange }: ReportDialogProps) {
  const [reason, setReason] = useState<ReportReason>('MALWARE');
  const [details, setDetails] = useState('');
  const [includeKey, setIncludeKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    const body: ReportRequest = { reason };
    if (details.trim()) body.details = details.trim();
    if (includeKey && dk) body.decryptionKey = b64urlEncode(dk);
    try {
      await api.post(`/drops/${encodeURIComponent(dropId)}/report`, body, {
        schema: ReportResponseSchema,
        anonymous: true,
      });
      toast.success('Report sent', { description: 'Thank you. A moderator will review it.' });
      setDetails('');
      setIncludeKey(false);
      onOpenChange(false);
    } catch (err) {
      setError(describeError(err, 'The report could not be sent. Please try again.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !busy && onOpenChange(o)}
      dismissible={!busy}
      title="Report this drop"
      description="Moderators can only see the files if you include the decryption key."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form="report-form" icon={Flag} loading={busy} variant="danger">
            Send report
          </Button>
        </>
      }
    >
      <form id="report-form" onSubmit={submit} className="space-y-4">
        {error ? (
          <Alert tone="danger" live="assertive">
            {error}
          </Alert>
        ) : null}
        <Select
          label="Reason"
          value={reason}
          onChange={(e) => setReason(e.target.value as ReportReason)}
          options={REASONS}
        />
        <Textarea
          label="Details"
          optional
          value={details}
          onChange={(e) => setDetails(e.target.value)}
          maxLength={LIMITS.MAX_REPORT_DETAILS_CHARS}
          showCount
          rows={3}
          hint="Don't include personal information."
        />
        <Checkbox
          label="Include the decryption key so moderators can review"
          description={
            dk
              ? 'Without it, moderators can only see sizes and dates, never the contents.'
              : 'Unlock the drop first to include its key.'
          }
          checked={includeKey}
          disabled={!dk}
          onChange={(e) => setIncludeKey(e.target.checked)}
        />
      </form>
    </Dialog>
  );
}
