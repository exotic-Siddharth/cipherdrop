/**
 * Upload worker (spec 11.3): encrypts every chunk with the packages/crypto STREAM functions and PUTs it
 * itself, so neither the AES work nor the network loop touches the UI thread.
 *
 * Protocol (module worker, one upload per worker instance):
 *   main -> worker  { type: 'start', job: UploadWorkerJob }  then optionally  { type: 'cancel' }
 *   worker -> main  { type: 'event', event: UploadEvent }      progress, cipher previews, retries
 *                   { type: 'done' }                           every chunk stored
 *                   { type: 'error', error: {code, message} }  fatal (after retries) or cancelled (ABORTED)
 *
 * Only worker-safe modules are imported (crypto/uploader -> lib/http, @cipherdrop/*): never lib/api or stores.
 */
import {
  serializeUploadError,
  uploadDropFiles,
  type SerializedUploadError,
  type UploadEvent,
  type UploadFileJob,
} from '../crypto/uploader';

export interface UploadWorkerJob {
  dropId: string;
  uploadToken: string;
  /** Raw DK bytes (copied by structured clone; never logged). */
  dk: Uint8Array;
  files: UploadFileJob[];
  /** Origin for the PUT URLs (the page passes window.location.origin). */
  baseUrl: string;
}

export type UploadWorkerRequest = { type: 'start'; job: UploadWorkerJob } | { type: 'cancel' };

export type UploadWorkerResponse =
  | { type: 'event'; event: UploadEvent }
  | { type: 'done' }
  | { type: 'error'; error: SerializedUploadError };

export interface UploadWorkerDeps {
  /** Test seam for the retry sleeps. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

/** The worker's message handler, separated from the global scope so node tests can drive it (R20). */
export function createUploadWorkerHandler(
  post: (msg: UploadWorkerResponse) => void,
  deps: UploadWorkerDeps = {},
): (msg: UploadWorkerRequest) => void {
  let controller: AbortController | null = null;
  let started = false;

  return (msg) => {
    if (msg.type === 'cancel') {
      controller?.abort();
      return;
    }
    if (msg.type !== 'start' || started) return;
    started = true;
    controller = new AbortController();
    const { job } = msg;
    uploadDropFiles({
      dropId: job.dropId,
      uploadToken: job.uploadToken,
      dk: job.dk,
      files: job.files,
      baseUrl: job.baseUrl,
      signal: controller.signal,
      sleep: deps.sleep,
      onEvent: (event) => post({ type: 'event', event }),
    }).then(
      () => post({ type: 'done' }),
      (err: unknown) => post({ type: 'error', error: serializeUploadError(err) }),
    );
  };
}

interface WorkerScopeLike {
  postMessage(msg: unknown): void;
  addEventListener(
    type: 'message',
    listener: (ev: MessageEvent<UploadWorkerRequest>) => void,
  ): void;
}

const scope = globalThis as unknown as { WorkerGlobalScope?: unknown } & WorkerScopeLike;
if (typeof scope.WorkerGlobalScope !== 'undefined') {
  const handle = createUploadWorkerHandler((msg) => scope.postMessage(msg));
  scope.addEventListener('message', (ev) => handle(ev.data));
}
