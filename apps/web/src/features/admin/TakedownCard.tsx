import { ModerationReasonSchema } from '@cipherdrop/shared';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Ban } from 'lucide-react';
import { useId, useState, type FormEvent } from 'react';
import { toast } from 'sonner';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { Input } from '../../components/ui/Input';
import { api } from '../../lib/api';
import { describeError } from '../../lib/errors';
import { queryKeys } from '../../lib/queryClient';
import { dropIdFromInput } from './dropInput';

/** Takedown by id (server-6): disable a drop without a report, for notices that arrive by other routes. */
export function TakedownCard() {
  const qc = useQueryClient();
  const formId = useId();
  const [link, setLink] = useState('');
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const dropId = dropIdFromInput(link);
  const reasonOk = ModerationReasonSchema.safeParse(reason).success;

  const takedown = useMutation({
    mutationFn: (vars: { dropId: string; reason: string }) =>
      api.post(`/admin/drops/${encodeURIComponent(vars.dropId)}/disable`, {
        reason: vars.reason,
      }),
    onSuccess: () => {
      toast.success('Drop taken down');
      setLink('');
      setReason('');
      setTouched(false);
      void qc.invalidateQueries({ queryKey: queryKeys.adminReports() });
      void qc.invalidateQueries({ queryKey: queryKeys.adminStats() });
      void qc.invalidateQueries({ queryKey: queryKeys.adminAudit() });
    },
    onError: (err) => setFailure(describeError(err)),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    setFailure(null);
    if (!dropId || !reasonOk) return;
    takedown.mutate({ dropId, reason: reason.trim() });
  };

  return (
    <Card as="section" aria-labelledby="takedown-title">
      <CardHeader
        icon={Ban}
        title={<span id="takedown-title">Take a drop down</span>}
        description="For a takedown notice without a report: the drop stops downloading and its files are deleted. Recorded in the audit log."
      />
      <form
        id={formId}
        onSubmit={submit}
        noValidate
        className="flex flex-col gap-4 px-5 py-4 sm:px-6"
      >
        <Input
          label="Drop link or id"
          autoComplete="off"
          value={link}
          onChange={(e) => setLink(e.target.value)}
          error={touched && !dropId ? 'Paste a drop link or its id.' : undefined}
          hint="The part after # (the key) is removed and never sent."
        />
        <Input
          label="Reason"
          autoComplete="off"
          maxLength={500}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          error={touched && !reasonOk ? 'Give a reason (for the audit log).' : undefined}
        />
        {failure ? (
          <Alert tone="danger" live="assertive">
            {failure}
          </Alert>
        ) : null}
        <div>
          <Button type="submit" variant="danger" icon={Ban} loading={takedown.isPending}>
            Take down
          </Button>
        </div>
      </form>
    </Card>
  );
}
