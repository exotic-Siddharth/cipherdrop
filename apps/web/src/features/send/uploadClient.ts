/**
 * Main-thread side of upload.worker: one module worker per upload, cancel through an AbortSignal, errors
 * mapped back from {code, message} (C1 note: structured clone drops prototypes and .code).
 */
import { deserializeUploadError, type UploadEvent } from '../../crypto/uploader';
import type {
  UploadWorkerJob,
  UploadWorkerRequest,
  UploadWorkerResponse,
} from '../../workers/upload.worker';

export type { UploadWorkerJob };

function abortError(): DOMException {
  return new DOMException('The operation was aborted.', 'AbortError');
}

/** Run one upload in a fresh worker. Resolves when every chunk is stored. */
export function runUploadInWorker(
  job: UploadWorkerJob,
  onEvent: (event: UploadEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const worker = new Worker(new URL('../../workers/upload.worker.ts', import.meta.url), {
      type: 'module',
      name: 'cipherdrop-upload',
    });
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      worker.terminate();
      fn();
    };
    const onAbort = () => {
      // Ask the worker to abort its PUTs, then terminate it (terminate also cancels its fetches).
      worker.postMessage({ type: 'cancel' } satisfies UploadWorkerRequest);
      finish(() => reject(abortError()));
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    worker.onmessage = (ev: MessageEvent<UploadWorkerResponse>) => {
      const msg = ev.data;
      if (msg.type === 'event') onEvent(msg.event);
      else if (msg.type === 'done') finish(resolve);
      else if (msg.type === 'error') finish(() => reject(deserializeUploadError(msg.error)));
    };
    worker.onerror = (ev) => {
      ev.preventDefault();
      finish(() =>
        reject(Object.assign(new Error('The upload worker failed to start.'), { code: 'UNKNOWN' })),
      );
    };
    worker.postMessage({ type: 'start', job } satisfies UploadWorkerRequest);
  });
}
