import { describe, expect, it } from 'vitest';
import { matchResumeFiles, type ResumeRecord } from './resumeRecord';

function record(files: Array<{ id: string; size: number; lastModified: number }>): ResumeRecord {
  return {
    dropId: 'd',
    uploadToken: 't',
    dk: 'k',
    files: files.map((f) => ({ ...f, chunkCount: 1 })),
    ownerToken: 'o',
    expiresAt: '2026-11-08T00:00:00.000Z',
    createdAt: '2026-11-07T00:00:00.000Z',
    maxDownloads: 1,
    passwordProtected: false,
    anonymous: true,
  };
}

describe('matchResumeFiles', () => {
  it('matches re-selected files to the record in record order', () => {
    const rec = record([
      { id: 'a', size: 10, lastModified: 1 },
      { id: 'b', size: 20, lastModified: 2 },
    ]);
    const b = { size: 20, lastModified: 2 };
    const a = { size: 10, lastModified: 1 };
    expect(matchResumeFiles(rec, [b, a])).toEqual([a, b]);
  });

  it('keeps same-size files with distinct mtimes resumable', () => {
    const rec = record([
      { id: 'a', size: 10, lastModified: 1 },
      { id: 'b', size: 10, lastModified: 2 },
    ]);
    const second = { size: 10, lastModified: 2 };
    const first = { size: 10, lastModified: 1 };
    expect(matchResumeFiles(rec, [second, first])).toEqual([first, second]);
  });

  it('refuses to resume when two record files share size and lastModified (C-19)', () => {
    // Re-picked in a different order, B and C would swap under each other's fileId (and nonces).
    const rec = record([
      { id: 'big', size: 1000, lastModified: 5 },
      { id: 'b', size: 10, lastModified: 7 },
      { id: 'c', size: 10, lastModified: 7 },
    ]);
    const files = [
      { size: 10, lastModified: 7 },
      { size: 10, lastModified: 7 },
      { size: 1000, lastModified: 5 },
    ];
    expect(matchResumeFiles(rec, files)).toBeNull();
  });
});
