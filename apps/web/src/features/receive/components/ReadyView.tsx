import { type Manifest, type ManifestFile } from '@cipherdrop/crypto';
import { DropMetaSchema, OpenResponseSchema } from '@cipherdrop/shared';
import {
  Download,
  Eye,
  Flag,
  HardDriveDownload,
  MessageSquareText,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Timer,
} from 'lucide-react';
import { useMemo, useRef, useState, type ReactNode } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  ConfirmDialog,
  EmptyState,
  ProgressBar,
} from '../../../components/ui';
import {
  DownloadSession,
  isGrantExpiredError,
  isIntegrityError,
  type DownloadGrant,
} from '../../../crypto/downloader';
import {
  createBlobSink,
  createFileSystemSink,
  needsSavePicker,
  pickSaveFile,
  saveFilePickerAvailable,
  type FileSink,
} from '../../../crypto/sinks';
import { api, isApiError } from '../../../lib/api';
import { describeError, isAbortError } from '../../../lib/errors';
import { saveBlob } from '../../../lib/files';
import {
  formatBytes,
  formatDate,
  formatPercent,
  formatRelative,
  pluralize,
} from '../../../lib/format';
import { sanitizeFilenames } from '../../../lib/sanitizeFilename';
import { FileList } from '../../send/components/FileList';
import { FilePreview } from './FilePreview';
import { ReportDialog } from './ReportDialog';

export const INTEGRITY_ERROR_TITLE =
  'This file was modified in transit or storage. Download blocked.';

type FileStatus =
  | { status: 'idle' }
  | { status: 'downloading'; written: number }
  | { status: 'verified'; blob: Blob | null }
  | { status: 'integrity' }
  | { status: 'error'; error: unknown }
  | { status: 'needs-save' }
  | { status: 'unsupported' };

export interface ReadyViewProps {
  dropId: string;
  dk: Uint8Array;
  manifest: Manifest;
  /** Public metadata (null in review mode). */
  meta: { downloadsRemaining: number; maxDownloads: number; expiresAt: string } | null;
  /** b64url authKey of a password drop, required by /open. */
  authKey: string | null;
  /** Admin review (R13): a non-consuming grant and a way to get a fresh one. */
  review: { grant: DownloadGrant; regrant: () => Promise<DownloadGrant> } | null;
}

export function ReadyView({ dropId, dk, manifest, meta, authKey, review }: ReadyViewProps) {
  const savedNames = useMemo(
    () => sanitizeFilenames(manifest.files.map((f) => f.name)),
    [manifest],
  );
  // C-03: a file over 256 MB cannot be saved without the save picker. Decide that from the manifest up
  // front, so the click never spends a download (a burn-after-read link) on a drop this browser can't save.
  const [files, setFiles] = useState<Record<string, FileStatus>>(() =>
    Object.fromEntries(
      manifest.files.map((f) => [
        f.id,
        (needsSavePicker(f.size) && !saveFilePickerAvailable()
          ? { status: 'unsupported' }
          : { status: 'idle' }) as FileStatus,
      ]),
    ),
  );
  const [remaining, setRemaining] = useState<number | null>(meta?.downloadsRemaining ?? null);
  const [started, setStarted] = useState(false);
  const [running, setRunning] = useState(false);
  const [openError, setOpenError] = useState<unknown>(null);
  const [confirmLast, setConfirmLast] = useState(false);
  const [reopen, setReopen] = useState<{ remaining: number } | null>(null);
  const [windowExpired, setWindowExpired] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);

  const session = useRef<DownloadSession | null>(null);
  session.current ??= new DownloadSession({
    dropId,
    dk,
    grant: review?.grant ?? null,
    open: review
      ? review.regrant
      : () =>
          api.post(`/drops/${encodeURIComponent(dropId)}/open`, authKey ? { authKey } : {}, {
            schema: OpenResponseSchema,
            anonymous: true,
          }),
  });

  const statusRef = useRef(files);
  const setFile = (id: string, s: FileStatus) => {
    statusRef.current = { ...statusRef.current, [id]: s };
    setFiles(statusRef.current);
  };
  const nameOf = (f: ManifestFile) => savedNames[manifest.files.indexOf(f)] ?? 'file';
  const isUnsupported = (f: ManifestFile) => needsSavePicker(f.size) && !saveFilePickerAvailable();

  /** Download one file. Rethrows GrantExpiredError so the caller can stop and ask (R12). */
  const runFile = async (f: ManifestFile, sink?: FileSink) => {
    setFile(f.id, { status: 'downloading', written: 0 });
    try {
      const blob = await session.current!.downloadFile(f, sink ?? createBlobSink(f.type), {
        onProgress: (written) => setFile(f.id, { status: 'downloading', written }),
      });
      if (blob) saveBlob(blob, nameOf(f));
      setFile(f.id, { status: 'verified', blob });
    } catch (err) {
      if (isGrantExpiredError(err)) {
        setFile(f.id, { status: 'idle' });
        throw err;
      }
      if (isIntegrityError(err)) setFile(f.id, { status: 'integrity' });
      else if (isAbortError(err)) setFile(f.id, { status: 'idle' });
      else setFile(f.id, { status: 'error', error: err });
    }
  };

  const handleExpired = async (): Promise<boolean> => {
    if (review) {
      await session.current!.open();
      return true;
    }
    try {
      const fresh = await api.get(`/drops/${encodeURIComponent(dropId)}`, {
        schema: DropMetaSchema,
        anonymous: true,
      });
      setRemaining(fresh.downloadsRemaining);
      if (fresh.downloadsRemaining > 0 && fresh.status === 'READY') {
        setReopen({ remaining: fresh.downloadsRemaining });
      } else {
        setWindowExpired(true);
      }
    } catch {
      setWindowExpired(true);
    }
    return false;
  };

  const downloadAll = async () => {
    if (!session.current!.currentGrant && manifest.files.some((f) => isUnsupported(f))) return;
    setStarted(true);
    setRunning(true);
    setOpenError(null);
    try {
      const s = session.current!;
      if (!s.currentGrant) {
        const grant = await s.open();
        if (grant.downloadsRemaining !== undefined) setRemaining(grant.downloadsRemaining);
      }
      for (const f of manifest.files) {
        const current = statusRef.current[f.id];
        if (current && (current.status === 'verified' || current.status === 'integrity')) continue;
        if (needsSavePicker(f.size)) {
          setFile(f.id, { status: saveFilePickerAvailable() ? 'needs-save' : 'unsupported' });
          continue;
        }
        try {
          await runFile(f);
        } catch (err) {
          if (isGrantExpiredError(err)) {
            if (await handleExpired()) {
              await runFile(f).catch(() => undefined);
              continue;
            }
            return;
          }
          throw err;
        }
      }
    } catch (err) {
      setOpenError(err);
    } finally {
      setRunning(false);
    }
  };

  /** R22: showSaveFilePicker must be the first thing the click handler does (transient activation). */
  const saveLarge = (f: ManifestFile) => {
    const picked = pickSaveFile(nameOf(f));
    void (async () => {
      let handle;
      try {
        handle = await picked;
      } catch (err) {
        if (!isAbortError(err)) setFile(f.id, { status: 'error', error: err });
        return;
      }
      try {
        await runFile(f, createFileSystemSink(handle));
      } catch (err) {
        if (isGrantExpiredError(err)) {
          await handleExpired();
          setFile(f.id, { status: 'needs-save' });
        }
      }
    })();
  };

  const retryFile = (f: ManifestFile) => {
    if (needsSavePicker(f.size)) {
      saveLarge(f);
      return;
    }
    void runFile(f).catch(async (err: unknown) => {
      if (isGrantExpiredError(err)) await handleExpired();
    });
  };

  const onDownloadClick = () => {
    if (!review && remaining === 1 && !session.current?.currentGrant) setConfirmLast(true);
    else void downloadAll();
  };

  const statuses = manifest.files.map((f) => files[f.id] ?? { status: 'idle' as const });
  const anyIntegrity = statuses.some((s) => s.status === 'integrity');
  const allVerified = statuses.every((s) => s.status === 'verified');
  const totalBytes = manifest.files.reduce((n, f) => n + f.size, 0);
  // Nothing was opened yet and a file can't be saved here: keep the download untouched until the user
  // switches browser. (Review mode and a session that already holds a grant are not blocked.)
  const blockedUpfront =
    !review && !session.current?.currentGrant && manifest.files.some((f) => isUnsupported(f));

  if (windowExpired) {
    return (
      <Card>
        <EmptyState
          icon={Timer}
          tone="warning"
          title="Your download window expired"
          description="The download took longer than its window allows, and this drop has no downloads left. Ask the sender for a new link."
        />
      </Card>
    );
  }

  const fileItems = manifest.files.map((f, i) => {
    const s = statuses[i]!;
    let detail: ReactNode = null;
    let trailing: ReactNode = null;
    switch (s.status) {
      case 'downloading': {
        const ratio = f.size > 0 ? s.written / f.size : 0;
        detail = (
          <div className="space-y-1">
            <ProgressBar
              label={`Decrypting ${nameOf(f)}`}
              hideLabel
              value={ratio * 100}
              size="sm"
            />
            <p className="text-xs text-muted tabular-nums">
              Downloading and decrypting {formatPercent(ratio)}
            </p>
          </div>
        );
        break;
      }
      case 'verified':
        trailing = (
          <>
            <Badge tone="success" icon={ShieldCheck}>
              Integrity verified
            </Badge>
            {s.blob ? (
              <Button
                variant="ghost"
                size="icon-sm"
                icon={Download}
                aria-label={`Save ${nameOf(f)} again`}
                onClick={() => saveBlob(s.blob!, nameOf(f))}
              />
            ) : null}
          </>
        );
        detail = s.blob ? <FilePreview blob={s.blob} type={f.type} name={nameOf(f)} /> : null;
        break;
      case 'integrity':
        trailing = (
          <Badge tone="danger" icon={ShieldAlert}>
            Blocked
          </Badge>
        );
        break;
      case 'error':
        detail = (
          <p className="text-sm text-danger-ink" role="alert">
            {describeError(s.error, 'The download failed.')}
          </p>
        );
        trailing = (
          <Button size="sm" variant="outline" icon={RotateCcw} onClick={() => retryFile(f)}>
            Try again
          </Button>
        );
        break;
      case 'needs-save':
        detail = (
          <p className="text-xs text-muted">
            Larger than 256 MB: choose where to save it, then it streams straight to disk.
          </p>
        );
        trailing = (
          <Button size="sm" icon={HardDriveDownload} onClick={() => saveLarge(f)}>
            Save...
          </Button>
        );
        break;
      case 'unsupported':
        detail = (
          <p className="text-sm text-warning-ink">
            This file is larger than 256 MB, and this browser can't save it straight to disk. Open
            the link in Chrome or Edge on a computer to download it.
          </p>
        );
        break;
      case 'idle':
        break;
    }
    return { key: f.id, name: nameOf(f), size: f.size, type: f.type, detail, trailing };
  });

  return (
    <div className="space-y-6">
      {anyIntegrity ? (
        <Alert tone="danger" prominent live="assertive" title={INTEGRITY_ERROR_TITLE}>
          The encrypted data failed its authentication check, so nothing was saved. Ask the sender
          to upload it again.
        </Alert>
      ) : null}

      {review ? (
        <Alert tone="warning" title="Review mode">
          You are reviewing a reported drop with the key its reporter supplied. This download does
          not count against the drop's limit and is recorded in the audit log.
        </Alert>
      ) : null}

      {manifest.note ? (
        <Card>
          <CardHeader icon={MessageSquareText} title="Note from the sender" titleAs="h2" />
          <CardContent className="pt-0">
            <p className="text-sm break-words whitespace-pre-wrap text-foreground">
              {manifest.note}
            </p>
          </CardContent>
        </Card>
      ) : null}

      <Card as="section" aria-labelledby="receive-files-title">
        <CardHeader
          title={<span id="receive-files-title">{pluralize(manifest.files.length, 'file')}</span>}
          description={
            <span>
              {formatBytes(totalBytes)}
              {meta ? (
                <>
                  {' · '}
                  {remaining ?? meta.downloadsRemaining} of {meta.maxDownloads} downloads left
                  {' · '}
                  <span title={formatDate(meta.expiresAt)}>
                    expires {formatRelative(meta.expiresAt)}
                  </span>
                </>
              ) : null}
            </span>
          }
          actions={
            allVerified ? (
              <Badge tone="success" icon={ShieldCheck} size="md">
                Integrity verified
              </Badge>
            ) : undefined
          }
        />
        <CardContent className="space-y-4 pt-0">
          <FileList items={fileItems} label="Files in this drop" />
          {blockedUpfront ? (
            <Alert tone="warning" title="This browser can't save every file in this drop">
              A file here is larger than 256 MB and this browser can't stream it straight to disk.
              Nothing was downloaded and the link still has all its downloads. Open the link in
              Chrome or Edge on a computer.
            </Alert>
          ) : null}
          {openError ? (
            <Alert tone="danger" live="assertive" title="The download could not start">
              {isApiError(openError) && openError.code === 'GONE'
                ? 'This drop has no downloads left or is no longer available.'
                : describeError(openError)}
            </Alert>
          ) : null}
          {!started || openError ? (
            <Button
              size="lg"
              fullWidth
              icon={Eye}
              onClick={onDownloadClick}
              loading={running}
              disabled={blockedUpfront || (isApiError(openError) && openError.code === 'GONE')}
            >
              Decrypt & download
            </Button>
          ) : running ? (
            <p className="text-center text-sm text-muted" aria-live="polite">
              Decrypting in your browser...
            </p>
          ) : null}
          <p className="text-center text-xs text-muted">
            Files are decrypted on this device and checked chunk by chunk. Anything modified is
            blocked, never saved.
          </p>
        </CardContent>
      </Card>

      {review ? null : (
        <div className="flex justify-center">
          <Button variant="ghost" size="sm" icon={Flag} onClick={() => setReportOpen(true)}>
            Report abuse
          </Button>
        </div>
      )}

      <ReportDialog dropId={dropId} dk={dk} open={reportOpen} onOpenChange={setReportOpen} />

      <ConfirmDialog
        open={confirmLast}
        onOpenChange={setConfirmLast}
        title="This is the last download"
        description="After this, the link stops working for everyone. Make sure you can save the files now."
        confirmLabel="Download now"
        onConfirm={() => {
          setConfirmLast(false);
          void downloadAll();
        }}
      />

      <ConfirmDialog
        open={reopen !== null}
        onOpenChange={(o) => !o && setReopen(null)}
        title="Your download window expired"
        description={
          reopen
            ? `Continuing re-opens the drop and uses one more download (${pluralize(reopen.remaining, 'download')} left).`
            : undefined
        }
        confirmLabel="Re-open and continue"
        onConfirm={async () => {
          const grant = await session.current!.open();
          if (grant.downloadsRemaining !== undefined) setRemaining(grant.downloadsRemaining);
          setReopen(null);
          void downloadAll();
        }}
      />
    </div>
  );
}
