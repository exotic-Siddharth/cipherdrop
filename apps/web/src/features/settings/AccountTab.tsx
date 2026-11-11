import { Monitor, Moon, Palette, Sun, Trash2, UserRound } from 'lucide-react';
import { useState } from 'react';
import { Alert } from '../../components/ui/Alert';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import { ProgressBar } from '../../components/ui/ProgressBar';
import { Select } from '../../components/ui/Select';
import { formatBytes, formatDate, formatPercent } from '../../lib/format';
import { useAuth } from '../../stores/auth';
import { useTheme, type ThemePreference } from '../../stores/theme';
import { useAccountActions } from '../account/useAccountActions';
import { ReauthDialog } from './ReauthDialog';

export const DELETE_PHRASE = 'DELETE';

const THEME_OPTIONS = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'system', label: 'Match my device' },
];

function ProfileCard() {
  const user = useAuth((s) => s.user);
  if (!user) return null;
  const ratio = user.storageQuotaBytes > 0 ? user.storageUsedBytes / user.storageQuotaBytes : 0;
  return (
    <Card as="section" aria-labelledby="profile-title">
      <CardHeader
        title={<span id="profile-title">Profile</span>}
        description="The email you log in with. It is never used for marketing."
        icon={UserRound}
        actions={user.role === 'ADMIN' ? <Badge tone="primary">Admin</Badge> : null}
      />
      <CardContent className="flex flex-col gap-5 pt-5">
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div className="min-w-0">
            <dt className="text-xs font-medium uppercase tracking-wide text-muted-strong">Email</dt>
            <dd className="mt-1 truncate font-medium text-foreground">{user.email}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-muted-strong">
              Member since
            </dt>
            <dd className="mt-1 font-medium text-foreground">{formatDate(user.createdAt)}</dd>
          </div>
        </dl>
        <ProgressBar
          label="Storage used"
          showValue
          value={user.storageUsedBytes}
          max={Math.max(user.storageQuotaBytes, 1)}
          valueText={`${formatBytes(user.storageUsedBytes)} of ${formatBytes(user.storageQuotaBytes)} (${formatPercent(ratio)})`}
          tone={ratio > 0.9 ? 'warning' : 'primary'}
        />
      </CardContent>
    </Card>
  );
}

function AppearanceCard() {
  const preference = useTheme((s) => s.preference);
  const setPreference = useTheme((s) => s.setPreference);
  const Icon = preference === 'dark' ? Moon : preference === 'light' ? Sun : Monitor;
  return (
    <Card as="section" aria-labelledby="appearance-title">
      <CardHeader
        title={<span id="appearance-title">Appearance</span>}
        description="Saved on this device only."
        icon={Palette}
      />
      <CardContent className="pt-5">
        <Select
          label="Theme"
          containerClassName="max-w-xs"
          options={THEME_OPTIONS}
          value={preference}
          hint={
            <span className="inline-flex items-center gap-1">
              <Icon className="size-3.5" aria-hidden="true" />
              Applied immediately.
            </span>
          }
          onChange={(e) => setPreference(e.target.value as ThemePreference)}
        />
      </CardContent>
    </Card>
  );
}

function DeleteAccountCard() {
  const actions = useAccountActions();
  const totpEnabled = useAuth((s) => s.user?.totpEnabled ?? false);
  const [open, setOpen] = useState(false);
  return (
    <>
      <Card as="section" aria-labelledby="delete-title" className="border-danger/35">
        <CardHeader
          title={<span id="delete-title">Delete account</span>}
          description="Permanently removes your account, every drop you created and the encrypted files behind them."
          icon={Trash2}
        />
        <CardContent className="flex flex-col items-start gap-4 pt-5">
          <Alert tone="danger" title="This cannot be undone" className="self-stretch">
            Links you shared stop working immediately. We cannot restore anything afterwards,
            because we never hold your keys.
          </Alert>
          <Button variant="danger" icon={Trash2} onClick={() => setOpen(true)}>
            Delete my account…
          </Button>
        </CardContent>
      </Card>
      <ReauthDialog
        open={open}
        onOpenChange={setOpen}
        title="Delete your account?"
        description="This permanently deletes your account, your drops and their files."
        confirmLabel="Delete everything"
        tone="danger"
        confirmPhrase={DELETE_PHRASE}
        password
        code={totpEnabled ? 'mfa' : false}
        busyHint="Checking your password locally…"
        onSubmit={({ password, code }) =>
          actions.deleteAccount(password, totpEnabled ? code : undefined)
        }
      />
    </>
  );
}

/** Spec 11.2 Account tab: delete with a typed confirmation + password + TOTP (plus profile and theme). */
export function AccountTab() {
  return (
    <div className="flex flex-col gap-6">
      <ProfileCard />
      <AppearanceCard />
      <DeleteAccountCard />
    </div>
  );
}
