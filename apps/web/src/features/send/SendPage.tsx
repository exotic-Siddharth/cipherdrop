/**
 * Send (spec 11.2 "/", 11.3 upload pipeline; R7, R11, R14).
 *
 * compose -> running (prepare on the main thread, encrypt + PUT in upload.worker, complete) -> done | error.
 * Signed in with a locked vault: an inline unlock blocks Encrypt & upload (R7). A sessionStorage record lets
 * a reload resume once the same files are re-selected (R11).
 */
import {
  downloadOptionsFor,
  expiryOptionsFor,
  LIMITS,
  type DownloadOption,
} from '@cipherdrop/shared';
import { Flame, KeyRound, Lock, RotateCcw, Timer, Trash2, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useBlocker } from 'react-router';
import { toast } from 'sonner';
import { PageHeader } from '../../components/layout/PageHeader';
import { PasswordStrength } from '../../components/PasswordStrength';
import {
  Alert,
  Button,
  Card,
  CardContent,
  CardHeader,
  ConfirmDialog,
  PasswordInput,
  Select,
  Switch,
  Textarea,
} from '../../components/ui';
import type { UploadEvent } from '../../crypto/uploader';
import { describeError, formatWait, isAbortError } from '../../lib/errors';
import { formatBytes, pluralize } from '../../lib/format';
import type { StrengthScore } from '../../lib/passwordStrength';
import { shareLinkFor } from '../../lib/links';
import { queryClient, queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { useDeviceDrops } from '../../stores/deviceDrops';
import { useLeaveGuard } from '../../stores/leaveGuard';
import { useVault } from '../../stores/vault';
import { validateNewPassword } from '../auth/passwordRules';
import { DeviceDropsList } from './components/DeviceDropsList';
import { Dropzone } from './components/Dropzone';
import { FileList } from './components/FileList';
import { SuccessCard } from './components/SuccessCard';
import { UploadProgress, type FileProgress } from './components/UploadProgress';
import { VaultUnlockInline } from './components/VaultUnlockInline';
import {
  clearResumeRecord,
  matchResumeFiles,
  readResumeRecord,
  type ResumeRecord,
} from './resumeRecord';
import {
  deleteDrop,
  dropCiphertextBytes,
  resumeDrop,
  startNewDrop,
  type SendPhase,
  type SendResult,
} from './sendFlow';

const POINTS = [
  { icon: Lock, text: 'AES-256-GCM in your browser' },
  { icon: KeyRound, text: 'The key stays in the link, or behind your password' },
  { icon: Timer, text: 'Links expire on schedule' },
  { icon: Flame, text: 'Burn after reading' },
];

const DEFAULT_EXPIRY_HOURS = 24;
const SPEED_WINDOW_MS = 5_000;

/** How the form came back; picks the focus target and the announcement (C-23). */
type ComposeAfter = 'cancel' | 'dismiss' | 'reset' | 'unlock';

type View =
  | { kind: 'compose'; after?: ComposeAfter }
  | { kind: 'running' }
  | { kind: 'done'; result: SendResult }
  | { kind: 'error'; error: unknown; canResume: boolean };

// Status-region announcements, worded unlike the visible headings so text locators match one element
// (Playwright strict mode).
const COMPOSE_STATUS: Record<ComposeAfter, string> = {
  cancel: 'Upload stopped. The send form is below.',
  dismiss: 'Error closed. The send form is below.',
  reset: 'Ready for a new drop. The send form is below.',
  unlock: 'Unlock your vault to send again.',
};

function errorText(err: unknown): string {
  if (err instanceof RangeError) {
    return 'The file names or the note are too long to encrypt. Shorten them and try again.';
  }
  return describeError(err, 'The upload failed. Please try again.');
}

function sameFile(a: File, b: File): boolean {
  return a.name === b.name && a.size === b.size && a.lastModified === b.lastModified;
}

export function Component() {
  const authStatus = useAuth((s) => s.status);
  const user = useAuth((s) => s.user);
  const accountKey = useVault((s) => s.accountKey);
  const signedIn = authStatus === 'authenticated' && user !== null;
  const kind = signedIn ? 'user' : 'anon';

  const [files, setFiles] = useState<File[]>([]);
  const [expiry, setExpiry] = useState(DEFAULT_EXPIRY_HOURS);
  const [maxDownloads, setMaxDownloads] = useState<DownloadOption>(1);
  const [usePassword, setUsePassword] = useState(false);
  const [password, setPassword] = useState('');
  const [passwordScore, setPasswordScore] = useState<StrengthScore | null>(null);
  const [note, setNote] = useState('');
  const [resume, setResume] = useState<ResumeRecord | null>(() => readResumeRecord());
  const [view, setView] = useState<View>({ kind: 'compose' });

  // Running state.
  const [phase, setPhase] = useState<SendPhase>('preparing');
  const [progress, setProgress] = useState<FileProgress[]>([]);
  const [speed, setSpeed] = useState<number | null>(null);
  const [hex, setHex] = useState<string | null>(null);
  const [retryNotice, setRetryNotice] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const activeRecord = useRef<ResumeRecord | null>(null);
  const samples = useRef<Array<{ t: number; bytes: number }>>([]);
  const uploadedTotal = useRef(0);

  const expiryOptions = useMemo(() => expiryOptionsFor(kind), [kind]);
  const downloadOptions = useMemo(() => downloadOptionsFor(kind), [kind]);
  const effectiveExpiry = expiryOptions.some((o) => o.hours === expiry)
    ? expiry
    : DEFAULT_EXPIRY_HOURS;
  const effectiveDownloads = downloadOptions.includes(maxDownloads) ? maxDownloads : 1;

  const maxBytes = useMemo(() => {
    if (!signedIn || !user) return LIMITS.ANON_MAX_DROP_BYTES;
    const quotaLeft = Math.max(0, user.storageQuotaBytes - user.storageUsedBytes);
    return Math.min(LIMITS.USER_MAX_DROP_BYTES, quotaLeft);
  }, [signedIn, user]);

  const plainTotal = files.reduce((n, f) => n + f.size, 0);
  const cipherTotal = dropCiphertextBytes(files);
  const overLimit = cipherTotal > maxBytes;
  const vaultLocked = signedIn && accountKey === null;
  const resumeMatch = resume ? matchResumeFiles(resume, files) : null;
  const passwordMissing = usePassword && password.length === 0;
  // Same floor as account passwords: a database copy lets an attacker guess the drop password offline.
  const passwordProblem = usePassword ? validateNewPassword(password, passwordScore) : null;
  const canSubmit =
    files.length > 0 &&
    !overLimit &&
    passwordProblem === null &&
    !vaultLocked &&
    authStatus !== 'booting';
  const running = view.kind === 'running';

  // In-app navigation to another page unmounts this one, which aborts the upload and drops the selected
  // files: ask first. Navigations that stay on "/" (the Send link, the logo) leave the upload alone.
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      running && currentLocation.pathname !== nextLocation.pathname,
  );
  // Sign out mid-upload asks through the same dialog (C-17); `leaveAsk` resolves the pending sign-out.
  const leaveAsk = useRef<((leave: boolean) => void) | null>(null);
  const [signOutAsked, setSignOutAsked] = useState(false);
  useEffect(() => {
    if (!running) return;
    useLeaveGuard.setState({
      confirmLeave: () =>
        new Promise<boolean>((resolve) => {
          leaveAsk.current?.(false);
          leaveAsk.current = resolve;
          setSignOutAsked(true);
        }),
    });
    return () => {
      useLeaveGuard.setState({ confirmLeave: null });
      leaveAsk.current?.(false);
      leaveAsk.current = null;
      setSignOutAsked(false);
    };
  }, [running]);
  // The dialog lives in the running view: when the upload ends while it is open, the user stays to see the
  // result. A blocker left 'blocked' would reopen the dialog at the next upload (C-17).
  useEffect(() => {
    if (!running && blocker.state === 'blocked') blocker.reset();
  }, [running, blocker]);

  // Leaving mid-upload loses the in-memory files; warn (resume after reload still works, R11).
  useEffect(() => {
    if (view.kind !== 'running') return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [view.kind]);

  useEffect(() => () => controller.current?.abort(), []);

  // Move focus to the new view (the focused button is unmounted by the swap), once per change. The done view's
  // SuccessCard focuses its own heading.
  const headerRef = useRef<HTMLDivElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const unlockRef = useRef<HTMLInputElement>(null);
  const previousKind = useRef<View['kind']>(view.kind);
  useEffect(() => {
    const before = previousKind.current;
    previousKind.current = view.kind;
    if (before === view.kind) return;
    if (view.kind === 'running') cancelRef.current?.focus();
    else if (view.kind === 'error') errorRef.current?.focus();
    else if (view.kind === 'compose') {
      ((view.after === 'unlock' ? unlockRef.current : null) ?? headerRef.current)?.focus();
    }
  }, [view]);

  const addFiles = (incoming: File[]) => {
    setFiles((current) => {
      const next = [...current];
      for (const f of incoming) if (!next.some((x) => sameFile(x, f))) next.push(f);
      if (next.length > LIMITS.MAX_FILES_PER_DROP) {
        toast.error(`A drop holds at most ${LIMITS.MAX_FILES_PER_DROP} files`, {
          description: 'The extra files were not added.',
        });
        return next.slice(0, LIMITS.MAX_FILES_PER_DROP);
      }
      return next;
    });
  };

  const onEvent = useCallback((e: UploadEvent) => {
    switch (e.type) {
      case 'chunk-encrypted':
        setProgress((p) =>
          p.map((f) => (f.id === e.fileId ? { ...f, encrypted: f.encrypted + e.plainBytes } : f)),
        );
        break;
      case 'chunk-uploaded': {
        setProgress((p) =>
          p.map((f) => (f.id === e.fileId ? { ...f, uploaded: f.uploaded + e.plainBytes } : f)),
        );
        setRetryNotice(null);
        uploadedTotal.current += e.plainBytes;
        const now = performance.now();
        const list = samples.current;
        list.push({ t: now, bytes: uploadedTotal.current });
        while (list.length > 2 && now - list[0]!.t > SPEED_WINDOW_MS) list.shift();
        const first = list[0]!;
        const dt = (now - first.t) / 1000;
        if (dt >= 0.5) setSpeed((uploadedTotal.current - first.bytes) / dt);
        break;
      }
      case 'cipher-preview':
        setHex(e.hex);
        break;
      case 'retry':
        setRetryNotice(
          `Connection trouble, retrying in ${formatWait(e.delayMs / 1000)} (attempt ${e.retry + 1} of 4).`,
        );
        break;
      case 'file-done':
        setProgress((p) => p.map((f) => (f.id === e.fileId ? { ...f, done: true } : f)));
        break;
    }
  }, []);

  const beginRun = () => {
    controller.current?.abort();
    const ctrl = new AbortController();
    controller.current = ctrl;
    activeRecord.current = null;
    samples.current = [{ t: performance.now(), bytes: 0 }];
    uploadedTotal.current = 0;
    setPhase('preparing');
    setProgress([]);
    setSpeed(null);
    setHex(null);
    setRetryNotice(null);
    setCancelling(false);
    setView({ kind: 'running' });
    return ctrl;
  };

  const callbacksFor = (selected: readonly File[]) => ({
    onPhase: setPhase,
    onEvent,
    onCreated: (record: ResumeRecord) => {
      activeRecord.current = record;
      setResume(null);
      setProgress(
        record.files.map((rf, i) => ({
          id: rf.id,
          name: selected[i]!.name,
          size: selected[i]!.size,
          type: selected[i]!.type,
          encrypted: 0,
          uploaded: 0,
          done: false,
        })),
      );
    },
  });

  const finish = (result: SendResult) => {
    controller.current = null;
    activeRecord.current = null; // completed: never resume or abandon it
    if (result.anonymous) {
      useDeviceDrops.getState().add({
        dropId: result.dropId,
        ownerToken: result.ownerToken,
        createdAt: result.createdAt,
        expiresAt: result.expiresAt,
      });
    } else {
      void queryClient.invalidateQueries({ queryKey: queryKeys.myDrops() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.me() });
    }
    setPassword('');
    setView({ kind: 'done', result });
  };

  const fail = (err: unknown, ctrl: AbortController) => {
    if (ctrl.signal.aborted || isAbortError(err)) return; // cancel() already reset the view
    controller.current = null;
    setView({ kind: 'error', error: err, canResume: activeRecord.current !== null });
  };

  /** Best-effort delete of an UPLOADING drop that a new drop replaces (DESIGN W2A: the old one is abandoned). */
  const abandonDrop = (record: ResumeRecord) => {
    void deleteDrop(record.dropId, record.ownerToken).catch(() => undefined);
  };

  /**
   * Every fresh drop starts here. `replaced` is an UPLOADING drop the new one supersedes (its record is
   * already cleared): it is deleted first, so its pending bytes no longer count against the quota.
   */
  const runNew = async (selected: File[], replaced?: ResumeRecord | null) => {
    const anonymous = !signedIn;
    const accountKey = anonymous ? null : useVault.getState().accountKey;
    if (!anonymous && accountKey === null) {
      // A signed-in drop needs the owner wrap (R7, C-38): back to compose, which shows the inline unlock.
      if (replaced) abandonDrop(replaced);
      controller.current = null;
      setView({ kind: 'compose', after: 'unlock' });
      return;
    }
    const ctrl = beginRun();
    if (replaced) await deleteDrop(replaced.dropId, replaced.ownerToken).catch(() => undefined);
    try {
      const result = await startNewDrop(
        {
          files: selected,
          note,
          expiresInHours: effectiveExpiry,
          maxDownloads: effectiveDownloads,
          password: usePassword ? password : null,
          accountKey,
          anonymous,
        },
        callbacksFor(selected),
        ctrl.signal,
      );
      finish(result);
    } catch (err) {
      fail(err, ctrl);
    }
  };

  const runResume = async (record: ResumeRecord, matched: File[]) => {
    const ctrl = beginRun();
    try {
      const result = await resumeDrop(record, matched, callbacksFor(matched), ctrl.signal);
      if (result === 'mismatch') {
        clearResumeRecord();
        setResume(null);
        toast.info('Starting a new drop', {
          description:
            "These files don't match the interrupted upload, so it can't be resumed safely.",
        });
        await runNew(files, record);
        return;
      }
      finish(result);
    } catch (err) {
      fail(err, ctrl);
    }
  };

  /** The interrupted drop, if any: after a failed upload it lives only in activeRecord and sessionStorage. */
  const liveRecord = () => activeRecord.current ?? resume ?? readResumeRecord();

  /** Same files resume the interrupted drop; other files replace it (deleted with the owner token, C-35). */
  const resumeOrReplace = (record: ResumeRecord | null) => {
    const matched = record ? matchResumeFiles(record, files) : null;
    if (record && matched) {
      void runResume(record, matched);
      return;
    }
    if (record) {
      clearResumeRecord();
      setResume(null);
    }
    void runNew(files, record);
  };

  const submit = () => {
    if (!canSubmit) return;
    resumeOrReplace(liveRecord());
  };

  const cancel = async () => {
    setCancelling(true);
    controller.current?.abort();
    controller.current = null;
    const record = activeRecord.current;
    clearResumeRecord();
    activeRecord.current = null;
    if (record) await deleteDrop(record.dropId, record.ownerToken).catch(() => undefined);
    setCancelling(false);
    setView({ kind: 'compose', after: 'cancel' });
    toast('Upload cancelled', { description: 'Nothing was kept on the server.' });
  };

  // A locked vault is handled in runNew (R7, C-38), the one path every fresh drop takes.
  const retryAfterError = () => resumeOrReplace(liveRecord());

  /** Back to the form; an interrupted drop shows its banner again, so Resume upload stays on offer. */
  const dismissError = () => {
    setResume(liveRecord());
    setView({ kind: 'compose', after: 'dismiss' });
  };

  const discardResume = () => {
    const record = resume;
    clearResumeRecord();
    setResume(null);
    if (record) abandonDrop(record);
  };

  const reset = () => {
    setFiles([]);
    setNote('');
    setPassword('');
    setUsePassword(false);
    setView({ kind: 'compose', after: 'reset' });
  };

  const statusText =
    view.kind === 'running'
      ? 'Upload started. Progress and a Cancel button are below.'
      : view.kind === 'done'
        ? 'Upload finished. The share link is below.'
        : view.kind === 'error'
          ? 'Upload failed. Details and a retry button are below.'
          : view.after
            ? COMPOSE_STATUS[view.after]
            : '';
  // One live region that stays mounted across view swaps, so a result inserted with its text is announced.
  const statusRegion = (
    <div data-testid="send-status" aria-live="polite" className="sr-only">
      {statusText}
    </div>
  );

  const answerSignOut = (leave: boolean) => {
    const resolve = leaveAsk.current;
    leaveAsk.current = null;
    setSignOutAsked(false);
    resolve?.(leave);
  };

  const leaveDialog = (
    <ConfirmDialog
      open={blocker.state === 'blocked' || signOutAsked}
      onOpenChange={(open) => {
        if (open) return;
        if (blocker.state === 'blocked') blocker.reset();
        if (signOutAsked) answerSignOut(false);
      }}
      title={signOutAsked ? 'Sign out and cancel the upload?' : 'Leave and cancel the upload?'}
      description={
        signOutAsked
          ? 'Your files are still being encrypted and uploaded. Signing out stops the upload and deletes the unfinished drop.'
          : 'Your files are still being encrypted and uploaded. Leaving this page stops it, and you would have to select the files again.'
      }
      confirmLabel={signOutAsked ? 'Sign out' : 'Leave'}
      cancelLabel="Keep uploading"
      tone="danger"
      onConfirm={async () => {
        if (blocker.state === 'blocked') blocker.proceed();
        else if (signOutAsked) {
          // Cancel (abort and delete the drop) while the session still exists, then let sign-out go on.
          const resolve = leaveAsk.current;
          leaveAsk.current = null;
          await cancel();
          resolve?.(true);
        }
        return false; // the dialog closes with the blocker or view state; never reset() after proceed()
      }}
    />
  );

  const header = (
    <div ref={headerRef} tabIndex={-1} className="outline-none">
      <PageHeader
        eyebrow="End-to-end encrypted"
        title="Send files"
        description="Share files only the recipient can read. Not even us."
      />
      <ul className="mb-6 flex flex-wrap gap-2" aria-label="How CipherDrop protects your files">
        {POINTS.map(({ icon: Icon, text }) => (
          <li
            key={text}
            className="inline-flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1.5 text-sm text-foreground shadow-card"
          >
            <Icon className="size-4 text-primary" aria-hidden="true" />
            {text}
          </li>
        ))}
      </ul>
    </div>
  );

  if (view.kind === 'running') {
    return (
      <>
        {statusRegion}
        {header}
        <div className="mx-auto max-w-3xl">
          <UploadProgress
            phase={phase}
            files={progress}
            speed={speed}
            hex={hex}
            retryNotice={retryNotice}
            onCancel={() => void cancel()}
            cancelling={cancelling}
            cancelRef={cancelRef}
          />
        </div>
        {leaveDialog}
      </>
    );
  }

  if (view.kind === 'done') {
    const r = view.result;
    const link = shareLinkFor(r.dropId, r.passwordProtected ? null : r.dk);
    return (
      <>
        {statusRegion}
        {header}
        <div className="mx-auto max-w-3xl space-y-6">
          <SuccessCard
            link={link}
            fileCount={r.fileCount}
            totalBytes={r.totalBytes}
            expiresAt={r.expiresAt}
            maxDownloads={r.maxDownloads}
            passwordProtected={r.passwordProtected}
            onDelete={async () => {
              await deleteDrop(r.dropId, r.ownerToken);
              useDeviceDrops.getState().remove(r.dropId);
              if (!r.anonymous) {
                void queryClient.invalidateQueries({ queryKey: queryKeys.myDrops() });
              }
              toast.success('Drop deleted');
              reset();
            }}
            onSendAnother={reset}
          />
          {!signedIn ? <DeviceDropsList /> : null}
        </div>
      </>
    );
  }

  const fileItems = files.map((f, i) => ({
    key: `${i}-${f.name}-${f.size}-${f.lastModified}`,
    name: f.name,
    size: f.size,
    type: f.type,
    trailing: (
      <Button
        variant="ghost"
        size="icon-sm"
        icon={X}
        aria-label={`Remove ${f.name}`}
        onClick={() => setFiles((cur) => cur.filter((x) => x !== f))}
      />
    ),
  }));

  const limitHint = `Up to ${LIMITS.MAX_FILES_PER_DROP} files and ${formatBytes(maxBytes)} per drop${
    signedIn ? '.' : '. Sign in for larger drops and longer links.'
  }`;

  return (
    <>
      {statusRegion}
      {header}

      {view.kind === 'error' ? (
        <div ref={errorRef} tabIndex={-1} className="mb-6 outline-none">
          <Alert
            tone="danger"
            live="assertive"
            title="The upload did not finish"
            action={
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  icon={RotateCcw}
                  onClick={retryAfterError}
                  disabled={files.length === 0}
                >
                  Try again
                </Button>
                <Button size="sm" variant="ghost" onClick={dismissError}>
                  Dismiss
                </Button>
              </div>
            }
          >
            {errorText(view.error)}
            {view.canResume
              ? ' Chunks that already arrived are kept, so trying again continues where it stopped.'
              : ''}
          </Alert>
        </div>
      ) : null}

      {resume ? (
        <Alert
          tone="info"
          title={
            resumeMatch ? 'Ready to resume your upload' : 'An upload in this tab was interrupted'
          }
          className="mb-6"
          action={
            <Button size="sm" variant="ghost" icon={Trash2} onClick={discardResume}>
              Discard it
            </Button>
          }
        >
          {resumeMatch
            ? 'These are the same files, so Resume upload continues where it stopped.'
            : `Select the same ${pluralize(resume.files.length, 'file')} again to resume it, or start a new drop.`}
        </Alert>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3" as="section" aria-labelledby="send-files-title">
          <CardHeader
            title={<span id="send-files-title">Files</span>}
            description={
              files.length > 0
                ? `${pluralize(files.length, 'file')} · ${formatBytes(plainTotal)}`
                : 'Nothing leaves your device until you press Encrypt & upload.'
            }
            actions={
              files.length > 0 ? (
                <Button variant="ghost" size="sm" onClick={() => setFiles([])}>
                  Clear all
                </Button>
              ) : undefined
            }
          />
          <CardContent className="space-y-4">
            <Dropzone onFiles={addFiles} hint={limitHint} compact={files.length > 0} />
            {files.length > 0 ? <FileList items={fileItems} label="Selected files" /> : null}
            {overLimit ? (
              <p className="text-sm text-danger-ink" role="alert">
                {signedIn && maxBytes < LIMITS.USER_MAX_DROP_BYTES
                  ? `This drop needs ${formatBytes(cipherTotal)} but only ${formatBytes(maxBytes)} of your storage is left.`
                  : `This drop is ${formatBytes(cipherTotal)} encrypted, above the ${formatBytes(maxBytes)} limit. Remove some files.`}
              </p>
            ) : null}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2" as="section" aria-labelledby="send-options-title">
          <CardHeader title={<span id="send-options-title">Options</span>} />
          <CardContent className="space-y-5">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
              <Select
                label="Expires after"
                value={String(effectiveExpiry)}
                onChange={(e) => setExpiry(Number(e.target.value))}
                options={expiryOptions.map((o) => ({ value: String(o.hours), label: o.label }))}
              />
              <Select
                label="Download limit"
                value={String(effectiveDownloads)}
                onChange={(e) => setMaxDownloads(Number(e.target.value) as DownloadOption)}
                options={downloadOptions.map((n) => ({
                  value: String(n),
                  label: n === 1 ? '1 — burn after reading' : `${n} downloads`,
                }))}
              />
            </div>
            {effectiveDownloads === 1 ? (
              <p className="-mt-2 flex items-center gap-2 rounded-md bg-primary/5 px-3 py-2 text-sm text-primary-ink">
                <Flame className="size-4 shrink-0" aria-hidden="true" />
                Burn after reading: the link stops working after the first download.
              </p>
            ) : null}

            <div className="space-y-3">
              <Switch
                checked={usePassword}
                onCheckedChange={setUsePassword}
                label="Protect with a password"
                description="The link then carries no key: recipients need the password too."
                layout="row"
              />
              {usePassword ? (
                <div className="space-y-2">
                  <PasswordInput
                    label="Password"
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    error={
                      passwordMissing
                        ? files.length > 0
                          ? 'Enter a password, or turn password protection off.'
                          : undefined
                        : (passwordProblem ?? undefined)
                    }
                  />
                  <PasswordStrength password={password} onScoreChange={setPasswordScore} />
                </div>
              ) : null}
            </div>

            <Textarea
              label="Note for the recipient"
              optional
              hint="Encrypted together with the file names."
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={LIMITS.MAX_NOTE_CHARS}
              showCount
              rows={3}
            />

            {vaultLocked ? <VaultUnlockInline inputRef={unlockRef} /> : null}

            <Button
              size="lg"
              fullWidth
              icon={resumeMatch ? RotateCcw : Lock}
              onClick={submit}
              disabled={!canSubmit}
            >
              {resumeMatch ? 'Resume upload' : 'Encrypt & upload'}
            </Button>
            {files.length === 0 ? (
              <p className="-mt-2 text-center text-xs text-muted">
                Add at least one file to continue.
              </p>
            ) : null}
          </CardContent>
        </Card>
      </div>

      {!signedIn ? (
        <div className="mt-6">
          <DeviceDropsList />
        </div>
      ) : null}
    </>
  );
}
