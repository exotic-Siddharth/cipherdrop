/**
 * Receive (spec 11.2 "/d/:id"; R12, R13, R14, R22).
 *
 * States: loading -> not found | gone (by reason) | still uploading | incomplete link | password prompt
 * -> ready (note, files, "N of M downloads left", Decrypt & download, previews, integrity verdicts, report).
 * `?review=1` for admins uses the non-consuming admin grant (R13). The DropMeta query is read once per page
 * view (dropMetaQueryOptions) so a consuming /open never flips the page to "used up" mid-download.
 */
import { AAD, b64urlEncode, decryptManifest, unwrapKey, type Manifest } from '@cipherdrop/crypto';
import {
  AdminGrantResponseSchema,
  DropMetaSchema,
  GoneDetailsSchema,
  UnlockResponseSchema,
  type DropMeta,
  type GoneReason,
} from '@cipherdrop/shared';
import { useQuery } from '@tanstack/react-query';
import {
  Ban,
  EyeOff,
  Clock3,
  FileQuestion,
  Flame,
  KeyRound,
  Link2Off,
  LoaderCircle,
  ShieldAlert,
  Trash2,
  type LucideIcon,
} from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { useLocation, useParams, useSearchParams } from 'react-router';
import { PageHeader } from '../../components/layout/PageHeader';
import { ButtonLink, Card, EmptyState, ErrorState, PageLoader } from '../../components/ui';
import { kdfClient } from '../../crypto/kdfClient';
import type { DownloadGrant } from '../../crypto/downloader';
import { api, isApiError } from '../../lib/api';
import { describeError } from '../../lib/errors';
import { readShareKey } from '../../lib/links';
import { dropMetaQueryOptions, queryClient, queryKeys } from '../../lib/queryClient';
import { useAuth } from '../../stores/auth';
import { PasswordPrompt } from './components/PasswordPrompt';
import { ReadyView } from './components/ReadyView';

const GONE_COPY: Record<GoneReason, { icon: LucideIcon; title: string; description: string }> = {
  EXPIRED: {
    icon: Clock3,
    title: 'This drop has expired',
    description: 'Its sender set an expiry time, and the encrypted files have been deleted.',
  },
  EXHAUSTED: {
    icon: Flame,
    title: 'All downloads have been used',
    description:
      'This drop allowed a limited number of downloads and they are used up. Ask the sender to send it again.',
  },
  DELETED: {
    icon: Trash2,
    title: 'This drop was deleted',
    description: 'The sender deleted it, together with the encrypted files.',
  },
  DISABLED: {
    icon: Ban,
    title: 'This drop was disabled',
    description: 'A moderator disabled it after a report. It can no longer be downloaded.',
  },
};

type Unlocked = { dk: Uint8Array; manifest: Manifest; authKey: string | null };

function StateCard({
  icon,
  title,
  description,
  tone,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  tone?: 'danger' | 'warning' | 'success';
  action?: ReactNode;
}) {
  return (
    <Card className="mx-auto max-w-2xl">
      <EmptyState icon={icon} title={title} description={description} tone={tone} action={action} />
    </Card>
  );
}

const sendLink = (
  <ButtonLink to="/" variant="outline">
    Send your own files
  </ButtonLink>
);

function goneReason(err: unknown): GoneReason | null {
  if (!isApiError(err) || err.status !== 410) return null;
  const parsed = GoneDetailsSchema.safeParse(err.details);
  return parsed.success ? parsed.data.reason : 'EXPIRED';
}

/** Decrypt the manifest of a key link (null key = incomplete link; IntegrityError = wrong key). */
function useKeyLinkManifest(meta: DropMeta | undefined, hash: string) {
  const [state, setState] = useState<
    | { kind: 'idle' }
    | { kind: 'incomplete' }
    | { kind: 'bad-key' }
    | { kind: 'ready'; value: Unlocked }
  >({ kind: 'idle' });
  useEffect(() => {
    if (!meta || meta.passwordProtected || meta.status !== 'READY') return;
    const dk = readShareKey(hash);
    if (!dk || !meta.encryptedManifest) {
      setState({ kind: 'incomplete' });
      return;
    }
    let alive = true;
    decryptManifest(dk, meta.encryptedManifest).then(
      (manifest) => alive && setState({ kind: 'ready', value: { dk, manifest, authKey: null } }),
      () => alive && setState({ kind: 'bad-key' }),
    );
    return () => {
      alive = false;
    };
  }, [meta, hash]);
  return state;
}

function ReviewView({ dropId, hash }: { dropId: string; hash: string }) {
  const dk = readShareKey(hash);
  const review = useQuery(
    {
      queryKey: ['admin', 'review', dropId],
      enabled: dk !== null,
      retry: false,
      ...dropMetaQueryOptions,
      queryFn: async () => {
        const grant = await api.post(
          `/admin/drops/${encodeURIComponent(dropId)}/grant`,
          undefined,
          {
            schema: AdminGrantResponseSchema,
          },
        );
        const manifest = await decryptManifest(dk!, grant.encryptedManifest);
        return { grant, manifest };
      },
    },
    queryClient,
  );
  if (!dk) {
    return (
      <StateCard
        icon={Link2Off}
        tone="warning"
        title="This review link is incomplete"
        description="The key after # is missing or cut short. Open the review from the reports table again."
      />
    );
  }
  if (review.isPending) return <PageLoader label="Opening the drop for review..." />;
  if (review.isError) {
    return (
      <Card className="mx-auto max-w-2xl">
        <ErrorState
          title="Could not open this drop for review"
          error={review.error}
          onRetry={() => void review.refetch()}
          retrying={review.isFetching}
        />
      </Card>
    );
  }
  const regrant = async (): Promise<DownloadGrant> => {
    const g = await api.post(`/admin/drops/${encodeURIComponent(dropId)}/grant`, undefined, {
      schema: AdminGrantResponseSchema,
    });
    return { downloadToken: g.downloadToken, expiresAt: g.expiresAt };
  };
  return (
    <ReadyView
      dropId={dropId}
      dk={dk}
      manifest={review.data.manifest}
      meta={null}
      authKey={null}
      review={{
        grant: {
          downloadToken: review.data.grant.downloadToken,
          expiresAt: review.data.grant.expiresAt,
        },
        regrant,
      }}
    />
  );
}

function PublicView({ dropId, hash }: { dropId: string; hash: string }) {
  const metaQuery = useQuery(
    {
      queryKey: queryKeys.dropMeta(dropId),
      queryFn: ({ signal }) =>
        api.get(`/drops/${encodeURIComponent(dropId)}`, {
          schema: DropMetaSchema,
          anonymous: true,
          signal,
        }),
      ...dropMetaQueryOptions,
    },
    queryClient,
  );
  const meta = metaQuery.data;
  const keyLink = useKeyLinkManifest(meta, hash);
  const [unlocked, setUnlocked] = useState<Unlocked | null>(null);
  const [pwError, setPwError] = useState<string | null>(null);
  const [shakeKey, setShakeKey] = useState(0);
  const [pwBusy, setPwBusy] = useState(false);

  if (metaQuery.isPending) return <PageLoader label="Loading the drop..." />;
  if (metaQuery.isError) {
    const err = metaQuery.error;
    if (isApiError(err) && err.status === 404) {
      return (
        <StateCard
          icon={FileQuestion}
          title="This drop doesn't exist"
          description="Check that you opened the whole link. Drops are removed for good once they expire or are deleted."
          action={sendLink}
        />
      );
    }
    const reason = goneReason(err);
    if (reason) {
      const copy = GONE_COPY[reason];
      return (
        <StateCard
          icon={copy.icon}
          tone={reason === 'DISABLED' ? 'danger' : undefined}
          title={copy.title}
          description={copy.description}
          action={sendLink}
        />
      );
    }
    return (
      <Card className="mx-auto max-w-2xl">
        <ErrorState
          title="Could not load this drop"
          error={err}
          onRetry={() => void metaQuery.refetch()}
          retrying={metaQuery.isFetching}
        />
      </Card>
    );
  }

  if (meta!.status === 'UPLOADING') {
    return (
      <StateCard
        icon={LoaderCircle}
        title="This drop is still uploading"
        description="The sender's upload hasn't finished yet. Try this link again in a little while."
      />
    );
  }
  if (meta!.status !== 'READY') {
    const copy = GONE_COPY[meta!.status as GoneReason] ?? GONE_COPY.EXPIRED;
    return (
      <StateCard
        icon={copy.icon}
        title={copy.title}
        description={copy.description}
        action={sendLink}
      />
    );
  }

  const m = meta!;
  const summary = {
    downloadsRemaining: m.downloadsRemaining,
    maxDownloads: m.maxDownloads,
    expiresAt: m.expiresAt,
  };

  if (m.passwordProtected) {
    if (unlocked) {
      return (
        <ReadyView
          dropId={dropId}
          dk={unlocked.dk}
          manifest={unlocked.manifest}
          meta={summary}
          authKey={unlocked.authKey}
          review={null}
        />
      );
    }
    const onUnlock = async (password: string) => {
      setPwBusy(true);
      setPwError(null);
      try {
        if (!m.passwordKdf) throw new Error('missing kdf');
        const keys = await kdfClient.deriveDropPasswordKeys(password, m.passwordKdf);
        const authKey = b64urlEncode(keys.authKey);
        const res = await api.post(
          `/drops/${encodeURIComponent(dropId)}/unlock`,
          { authKey },
          { schema: UnlockResponseSchema, anonymous: true },
        );
        const dk = await unwrapKey(keys.wrapKey, res.wrappedDropKey, AAD.WRAP_DROP_PASSWORD);
        const manifest = await decryptManifest(dk, res.encryptedManifest);
        setUnlocked({ dk, manifest, authKey });
      } catch (err) {
        const wrong =
          (isApiError(err) && err.status === 401) ||
          (err as { code?: unknown } | null)?.code === 'WRONG_PASSWORD';
        setPwError(
          wrong
            ? 'Wrong password. Check it with the sender and try again.'
            : describeError(err, 'Could not unlock this drop. Please try again.'),
        );
        if (wrong) setShakeKey((k) => k + 1);
      } finally {
        setPwBusy(false);
      }
    };
    return <PasswordPrompt onUnlock={onUnlock} error={pwError} shakeKey={shakeKey} busy={pwBusy} />;
  }

  if (keyLink.kind === 'incomplete') {
    return (
      <StateCard
        icon={Link2Off}
        tone="warning"
        title="This link is incomplete"
        description="The part after # holds the decryption key, and it is missing or cut short. Ask the sender to copy the whole link again."
      />
    );
  }
  if (keyLink.kind === 'bad-key') {
    return (
      <StateCard
        icon={ShieldAlert}
        tone="danger"
        title="This link's key doesn't open this drop"
        description="The key in the link is wrong, or the drop was modified. Ask the sender to copy the whole link again."
      />
    );
  }
  if (keyLink.kind === 'idle') return <PageLoader label="Decrypting the file list..." />;
  return (
    <ReadyView
      dropId={dropId}
      dk={keyLink.value.dk}
      manifest={keyLink.value.manifest}
      meta={summary}
      authKey={null}
      review={null}
    />
  );
}

export function Component() {
  const { id = '' } = useParams();
  const [params] = useSearchParams();
  const { hash } = useLocation();
  const authStatus = useAuth((s) => s.status);
  const role = useAuth((s) => s.user?.role);
  const wantsReview = params.get('review') === '1';

  let body: ReactNode;
  if (wantsReview && authStatus === 'booting')
    body = <PageLoader label="Checking your session..." />;
  else if (wantsReview && role === 'ADMIN') body = <ReviewView key={id} dropId={id} hash={hash} />;
  else body = <PublicView key={id} dropId={id} hash={hash} />;

  return (
    <>
      <PageHeader
        title="Receive files"
        description="Files are decrypted in your browser with the key from the link."
        icon={KeyRound}
      />
      {body}
      <p className="mt-8 flex items-center justify-center gap-1.5 text-center text-xs text-muted-strong">
        <EyeOff className="size-3.5" aria-hidden="true" />
        CipherDrop never sees the key, the file names or the contents, unless you include the key in
        an abuse report.
      </p>
    </>
  );
}
