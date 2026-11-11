import { AAD, decryptManifest, unwrapKey } from '@cipherdrop/crypto';
import type { OwnerDropSummary } from '@cipherdrop/shared';
import { useEffect, useState } from 'react';

export interface DecryptedDrop {
  names: string[];
  note: string | null;
  /** The drop key; only held while the vault is unlocked and zeroed on lock. */
  dk: Uint8Array;
}

/**
 * Per-drop display state, derived from the vault:
 * - `locked`: the vault is locked (R7), nothing is decrypted;
 * - `unavailable`: the drop was created without an unlocked vault, so there is no owner wrap;
 * - `pending`: decrypting;
 * - `error`: the owner wrap or manifest failed to decrypt (damaged data);
 * - `ready`: names decrypted locally.
 */
export type DropNameState =
  | { kind: 'locked' }
  | { kind: 'unavailable' }
  | { kind: 'pending' }
  | { kind: 'error' }
  | ({ kind: 'ready' } & DecryptedDrop);

type Entry = { kind: 'error' } | ({ kind: 'ready' } & DecryptedDrop);

async function decryptOne(accountKey: CryptoKey, drop: OwnerDropSummary): Promise<Entry> {
  if (!drop.ownerWrappedKey) return { kind: 'error' };
  let dk: Uint8Array | null = null;
  try {
    dk = await unwrapKey(accountKey, drop.ownerWrappedKey, AAD.WRAP_OWNER);
    const manifest = await decryptManifest(dk, drop.encryptedManifest);
    return {
      kind: 'ready',
      names: manifest.files.map((f) => f.name),
      note: manifest.note,
      dk,
    };
  } catch {
    dk?.fill(0);
    return { kind: 'error' };
  }
}

/**
 * Decrypt the file names of the listed drops with the vault's account key, entirely client-side. When the
 * account key disappears (auto-lock, manual lock, logout) every decrypted value is dropped and the drop keys
 * are zeroed; nothing navigates (R7).
 */
export function useOwnerDropNames(
  drops: readonly OwnerDropSummary[],
  accountKey: CryptoKey | null,
): (id: string) => DropNameState {
  const [entries, setEntries] = useState<ReadonlyMap<string, Entry>>(new Map());

  // Forget everything the moment the vault locks (or switches to another key).
  useEffect(() => {
    return () => {
      setEntries((prev) => {
        for (const entry of prev.values()) if (entry.kind === 'ready') entry.dk.fill(0);
        return prev.size === 0 ? prev : new Map();
      });
    };
  }, [accountKey]);

  useEffect(() => {
    if (!accountKey) return;
    let cancelled = false;
    const todo = drops.filter((d) => d.ownerWrappedKey && !entries.has(d.id));
    if (todo.length === 0) return;
    void (async () => {
      const done: Array<[string, Entry]> = [];
      for (const drop of todo) {
        const entry = await decryptOne(accountKey, drop);
        if (cancelled) {
          if (entry.kind === 'ready') entry.dk.fill(0);
          return;
        }
        done.push([drop.id, entry]);
      }
      setEntries((prev) => {
        const next = new Map(prev);
        for (const [id, entry] of done) next.set(id, entry);
        return next;
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [drops, accountKey, entries]);

  return (id) => {
    const drop = drops.find((d) => d.id === id);
    if (!drop?.ownerWrappedKey) return { kind: 'unavailable' };
    if (!accountKey) return { kind: 'locked' };
    return entries.get(id) ?? { kind: 'pending' };
  };
}
