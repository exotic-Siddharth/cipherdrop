// @vitest-environment node
import {
  b64urlEncode,
  createPasswordProtection,
  deriveAccountKeys,
  createAccountBundle,
  KDF_MIN,
  KdfParamsError,
  WrongPasswordError,
} from '@cipherdrop/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleKdfRequest, serializeKdfError } from '../workers/kdf.worker';
import { kdfClient, resetKdfWorker } from './kdfClient';

/** A Worker stand-in that runs the real worker logic in-process and clones messages like a real worker. */
class InProcessWorker {
  static created = 0;
  protected listeners: Record<string, Array<(ev: unknown) => void>> = {};
  constructor() {
    InProcessWorker.created += 1;
  }
  addEventListener(type: string, fn: (ev: unknown) => void) {
    (this.listeners[type] ??= []).push(fn);
  }
  removeEventListener() {}
  terminate() {}
  postMessage(raw: { id: number; request: Parameters<typeof handleKdfRequest>[0] }) {
    const msg = structuredClone(raw);
    void handleKdfRequest(msg.request).then(
      (result) => this.reply({ id: msg.id, ok: true, result }),
      (err: unknown) => this.reply({ id: msg.id, ok: false, error: serializeKdfError(err) }),
    );
  }
  private reply(data: unknown) {
    const cloned = structuredClone(data);
    queueMicrotask(() => this.listeners['message']?.forEach((fn) => fn({ data: cloned })));
  }
}

beforeEach(() => {
  InProcessWorker.created = 0;
  vi.stubGlobal('Worker', InProcessWorker);
  resetKdfWorker();
});
afterEach(() => resetKdfWorker());

const kdf = {
  salt: b64urlEncode(new Uint8Array(16).fill(3)),
  memoryKiB: KDF_MIN.memoryKiB,
  iterations: KDF_MIN.iterations,
  parallelism: KDF_MIN.parallelism,
};

describe('kdfClient', () => {
  it('worker RPC returns same authKey as direct packages/crypto call', async () => {
    const direct = await deriveAccountKeys('pässword-1', kdf);
    const viaWorker = await kdfClient.deriveAccountKeys('pässword-1', kdf);
    expect(b64urlEncode(viaWorker.authKey)).toBe(b64urlEncode(direct.authKey));
    expect(viaWorker.encKey.extractable).toBe(false);
  });

  it('creates one lazy worker and reuses it for concurrent requests', async () => {
    expect(InProcessWorker.created).toBe(0);
    const [a, b] = await Promise.all([
      kdfClient.deriveAccountKeys('one-password', kdf),
      kdfClient.deriveAccountKeys('two-password', kdf),
    ]);
    expect(InProcessWorker.created).toBe(1);
    // Responses are matched to requests by id, not by arrival order.
    expect(b64urlEncode(a.authKey)).toBe(
      b64urlEncode((await deriveAccountKeys('one-password', kdf)).authKey),
    );
    expect(b64urlEncode(b.authKey)).toBe(
      b64urlEncode((await deriveAccountKeys('two-password', kdf)).authKey),
    );
  });

  it('creates an account bundle and password protection like the direct calls', async () => {
    const bundle = await kdfClient.createAccountBundle('registration-pw', KDF_MIN);
    expect(bundle.kdf.memoryKiB).toBe(KDF_MIN.memoryKiB);
    expect(bundle.recoveryKey).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
    const protection = await kdfClient.createPasswordProtection(
      new Uint8Array(32).fill(9),
      'drop-pw',
      KDF_MIN,
    );
    const direct = await createPasswordProtection(new Uint8Array(32).fill(9), 'drop-pw', KDF_MIN);
    expect(protection.wrappedDropKey).toHaveLength(direct.wrappedDropKey.length);
    expect(protection.kdf.memoryKiB).toBe(KDF_MIN.memoryKiB);
  });

  it('maps errors back to the crypto error classes by code', async () => {
    const bundle = await createAccountBundle('right-password', KDF_MIN);
    await expect(
      kdfClient.unlockVault('wrong-password', bundle.kdf, bundle.wrappedAccountKey),
    ).rejects.toBeInstanceOf(WrongPasswordError);
    await expect(
      kdfClient.deriveAccountKeys('pw', { ...kdf, memoryKiB: 8 }),
    ).rejects.toBeInstanceOf(KdfParamsError);
  });

  it('rejects pending requests when the worker errors out and recreates it afterwards', async () => {
    class DyingWorker extends InProcessWorker {
      override postMessage() {
        queueMicrotask(() => this.listeners['error']?.forEach((fn) => fn({ message: 'boom' })));
      }
    }
    vi.stubGlobal('Worker', DyingWorker);
    await expect(kdfClient.deriveAccountKeys('pw', kdf)).rejects.toThrow(/key derivation/i);
    vi.stubGlobal('Worker', InProcessWorker);
    const keys = await kdfClient.deriveAccountKeys('pw', kdf);
    expect(keys.authKey).toHaveLength(32);
  });
});
