/**
 * "Sent from this device" (spec 11.2): anonymous drops this browser created, so the sender can delete them
 * later with the owner token. Persisted in localStorage under DEVICE_DROPS_STORAGE_KEY.
 *
 * Only {dropId, ownerToken, createdAt, expiresAt} is ever stored: NO file names, NO keys, NO links. The
 * owner token can delete the drop but cannot decrypt it. Expired entries are pruned on load and on add.
 */
import { create } from 'zustand';

export const DEVICE_DROPS_STORAGE_KEY = 'cd-device-drops';
/** Oldest entries are dropped beyond this many. */
export const MAX_DEVICE_DROPS = 50;

export interface DeviceDrop {
  dropId: string;
  ownerToken: string;
  /** ISO date-time. */
  createdAt: string;
  /** ISO date-time. */
  expiresAt: string;
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function isDeviceDrop(v: unknown): v is DeviceDrop {
  if (!v || typeof v !== 'object') return false;
  const d = v as Record<string, unknown>;
  return (
    typeof d.dropId === 'string' &&
    d.dropId.length <= 64 &&
    B64URL_RE.test(d.dropId) &&
    typeof d.ownerToken === 'string' &&
    d.ownerToken.length <= 128 &&
    B64URL_RE.test(d.ownerToken) &&
    typeof d.createdAt === 'string' &&
    !Number.isNaN(Date.parse(d.createdAt)) &&
    typeof d.expiresAt === 'string' &&
    !Number.isNaN(Date.parse(d.expiresAt))
  );
}

/** Copy exactly the four allowed fields (callers may pass richer objects). */
function pick(d: DeviceDrop): DeviceDrop {
  return {
    dropId: d.dropId,
    ownerToken: d.ownerToken,
    createdAt: d.createdAt,
    expiresAt: d.expiresAt,
  };
}

function live(drops: DeviceDrop[], now: number): DeviceDrop[] {
  return drops.filter((d) => Date.parse(d.expiresAt) > now);
}

export function readDeviceDrops(now: number = Date.now()): DeviceDrop[] {
  try {
    const raw = window.localStorage.getItem(DEVICE_DROPS_STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return live(parsed.filter(isDeviceDrop).map(pick), now);
  } catch {
    return [];
  }
}

function write(drops: DeviceDrop[]): void {
  try {
    if (drops.length === 0) window.localStorage.removeItem(DEVICE_DROPS_STORAGE_KEY);
    else window.localStorage.setItem(DEVICE_DROPS_STORAGE_KEY, JSON.stringify(drops));
  } catch {
    // Storage full or blocked: the list simply is not remembered.
  }
}

export interface DeviceDropsState {
  /** Newest first. */
  drops: DeviceDrop[];
  add: (drop: DeviceDrop) => void;
  remove: (dropId: string) => void;
  /** Re-read storage (another tab changed it) and drop expired entries. */
  sync: (now?: number) => void;
}

export const useDeviceDrops = create<DeviceDropsState>()((set, get) => ({
  drops: typeof window === 'undefined' ? [] : readDeviceDrops(),
  add: (drop) => {
    if (!isDeviceDrop(drop)) throw new TypeError('Invalid device drop');
    const next = [
      pick(drop),
      ...live(get().drops, Date.now()).filter((d) => d.dropId !== drop.dropId),
    ].slice(0, MAX_DEVICE_DROPS);
    write(next);
    set({ drops: next });
  },
  remove: (dropId) => {
    const next = get().drops.filter((d) => d.dropId !== dropId);
    write(next);
    set({ drops: next });
  },
  sync: (now = Date.now()) => {
    const next = readDeviceDrops(now);
    write(next);
    set({ drops: next });
  },
}));
