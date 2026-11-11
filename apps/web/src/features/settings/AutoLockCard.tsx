import { AUTO_LOCK_OPTIONS, MeResponseSchema, type AutoLockMinutes } from '@cipherdrop/shared';
import { useMutation } from '@tanstack/react-query';
import { Timer } from 'lucide-react';
import { toast } from 'sonner';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { Select } from '../../components/ui/Select';
import { api } from '../../lib/api';
import { describeError } from '../../lib/errors';
import { useAuth } from '../../stores/auth';

const OPTIONS = AUTO_LOCK_OPTIONS.map((m) => ({
  value: String(m),
  label: m === 60 ? 'After 1 hour of inactivity' : `After ${m} minutes of inactivity`,
}));

/** Vault auto-lock (5 / 15 / 60 minutes). Locking never signs you out: the password unlocks it again. */
export function AutoLockCard() {
  const minutes = useAuth((s) => s.user?.autoLockMinutes ?? 15);
  const save = useMutation({
    mutationFn: (autoLockMinutes: AutoLockMinutes) =>
      api.patch('/me/settings', { autoLockMinutes }, { schema: MeResponseSchema }),
    onSuccess: ({ user }) => {
      useAuth.getState().setUser(user);
      toast.success('Auto-lock updated');
    },
    onError: (err) => toast.error(describeError(err)),
  });

  return (
    <Card as="section" aria-labelledby="autolock-title">
      <CardHeader
        title={<span id="autolock-title">Auto-lock</span>}
        description="When you are idle, your account key is removed from this tab and the vault locks. You unlock it again with your password."
        icon={Timer}
      />
      <CardContent className="pt-5">
        <Select
          label="Lock the vault"
          containerClassName="max-w-sm"
          options={OPTIONS}
          value={String(minutes)}
          disabled={save.isPending}
          onChange={(e) => save.mutate(Number(e.target.value) as AutoLockMinutes)}
        />
      </CardContent>
    </Card>
  );
}
