import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEVICE_DROPS_STORAGE_KEY,
  MAX_DEVICE_DROPS,
  readDeviceDrops,
  useDeviceDrops,
  type DeviceDrop,
} from './deviceDrops';

const future = () => new Date(Date.now() + 3_600_000).toISOString();
const past = () => new Date(Date.now() - 1000).toISOString();

function drop(i: number, expiresAt = future()): DeviceDrop {
  return {
    dropId: `drop${String(i).padStart(18, '0')}`,
    ownerToken: 'o'.repeat(43),
    createdAt: new Date().toISOString(),
    expiresAt,
  };
}

beforeEach(() => {
  window.localStorage.clear();
  useDeviceDrops.setState({ drops: [] });
});
afterEach(() => window.localStorage.clear());

describe('deviceDrops store', () => {
  it('adds newest first, persists, and removes', () => {
    useDeviceDrops.getState().add(drop(1));
    useDeviceDrops.getState().add(drop(2));
    expect(useDeviceDrops.getState().drops.map((d) => d.dropId)).toEqual([
      drop(2).dropId,
      drop(1).dropId,
    ]);
    expect(readDeviceDrops()).toHaveLength(2);
    useDeviceDrops.getState().remove(drop(2).dropId);
    expect(readDeviceDrops().map((d) => d.dropId)).toEqual([drop(1).dropId]);
    useDeviceDrops.getState().remove(drop(1).dropId);
    expect(window.localStorage.getItem(DEVICE_DROPS_STORAGE_KEY)).toBeNull();
  });

  it('never stores names, keys or links, even if a caller passes them', () => {
    const rich = {
      ...drop(1),
      name: 'secret.pdf',
      dk: 'k'.repeat(43),
      link: 'https://x/d/1#key',
    } as DeviceDrop;
    useDeviceDrops.getState().add(rich);
    const raw = window.localStorage.getItem(DEVICE_DROPS_STORAGE_KEY)!;
    expect(raw).not.toContain('secret.pdf');
    expect(raw).not.toContain('k'.repeat(43));
    expect(raw).not.toContain('#key');
    expect(Object.keys(JSON.parse(raw)[0]).sort()).toEqual(
      ['createdAt', 'dropId', 'expiresAt', 'ownerToken'].sort(),
    );
  });

  it('prunes expired entries and ignores corrupt storage', () => {
    window.localStorage.setItem(
      DEVICE_DROPS_STORAGE_KEY,
      JSON.stringify([drop(1, past()), drop(2), { dropId: '../x', ownerToken: 1 }, 'junk']),
    );
    expect(readDeviceDrops().map((d) => d.dropId)).toEqual([drop(2).dropId]);
    window.localStorage.setItem(DEVICE_DROPS_STORAGE_KEY, '{not json');
    expect(readDeviceDrops()).toEqual([]);
    useDeviceDrops.getState().sync();
    expect(useDeviceDrops.getState().drops).toEqual([]);
  });

  it('re-adding a drop replaces it, and the list is capped', () => {
    for (let i = 0; i < MAX_DEVICE_DROPS + 5; i++) useDeviceDrops.getState().add(drop(i));
    useDeviceDrops.getState().add(drop(10));
    const ids = useDeviceDrops.getState().drops.map((d) => d.dropId);
    expect(ids).toHaveLength(MAX_DEVICE_DROPS);
    expect(ids[0]).toBe(drop(10).dropId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('rejects malformed entries', () => {
    expect(() => useDeviceDrops.getState().add({ ...drop(1), dropId: 'a/b' })).toThrow(TypeError);
  });
});
