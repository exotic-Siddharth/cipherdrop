// @vitest-environment node
import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ZodError } from 'zod';
import { IntegrityError } from './errors';
import { deriveManifestKey, generateDropKey, generateFileId } from './keys';
import { decryptManifest, encryptManifest, type Manifest, type ManifestFile } from './manifest';

const MiB4 = 4 * 1024 * 1024;
const random = (n: number) => new Uint8Array(nodeRandomBytes(n));
const chars = (...codes: number[]) => String.fromCharCode(...codes);

function file(overrides: Partial<ManifestFile> = {}): ManifestFile {
  return {
    id: generateFileId(),
    name: 'report.pdf',
    size: 10,
    type: 'application/pdf',
    lastModified: 1_700_000_000_000,
    chunkSize: MiB4,
    chunkCount: 1,
    ...overrides,
  };
}

function manifest(files: ManifestFile[] = [file()], note: string | null = null): Manifest {
  return { v: 1, createdAt: 1_762_500_000_000, note, files };
}

/** Seal arbitrary bytes exactly as spec 7.3 describes, WITHOUT encryptManifest's validation. */
async function sealRaw(
  dk: Uint8Array,
  plaintext: string | Uint8Array,
  aad = 'cipherdrop/v1/manifest',
) {
  const key = await deriveManifestKey(dk);
  const nonce = random(12);
  const data = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(aad) },
    key,
    new Uint8Array(data),
  );
  return Buffer.concat([nonce, new Uint8Array(ct)]).toString('base64url');
}

describe('manifest', () => {
  it('roundtrips awkward names, a 0-byte file, duplicate names and a note', async () => {
    const dk = generateDropKey();
    const m = manifest(
      [
        file({ name: `résumé 😀 עברית ${chars(0x202e)}txt.exe`, size: 0, type: '' }),
        file({ name: '../../etc/passwd', size: MiB4 + 1, chunkCount: 2 }),
        file({ name: 'CON.txt' }),
        file({ name: 'CON.txt' }),
        file({ name: `tab${chars(9)}nul${chars(0)}bell${chars(7)}`, type: 'text/plain' }),
        file({ name: 'x'.repeat(1024) }),
        file({ name: `${chars(0xd800)} lone surrogate` }),
      ],
      'Hi! 👋\nline two',
    );
    const blob = await encryptManifest(dk, m);
    expect(blob).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(await decryptManifest(dk, blob)).toEqual(m);
  });

  it('uses a fresh random nonce for every encryption', async () => {
    const dk = generateDropKey();
    const m = manifest();
    const a = await encryptManifest(dk, m);
    const b = await encryptManifest(dk, m);
    expect(Buffer.from(a, 'base64url').subarray(0, 12)).not.toEqual(
      Buffer.from(b, 'base64url').subarray(0, 12),
    );
    expect(await decryptManifest(dk, b)).toEqual(m);
  });

  it('a 20-file manifest with 1024-char names and a 2000-char note fits in 64 KiB', async () => {
    const dk = generateDropKey();
    const m = manifest(
      Array.from({ length: 20 }, () => file({ name: 'n'.repeat(1024) })),
      'z'.repeat(2000),
    );
    const blob = await encryptManifest(dk, m);
    expect(blob.length).toBeLessThanOrEqual(65_536);
    expect(await decryptManifest(dk, blob)).toEqual(m);
  });

  it('refuses to encrypt a manifest whose blob would exceed 64 KiB', async () => {
    // 20 names of 1024 CJK characters: 3 UTF-8 bytes each, about 82 000 b64url chars in total.
    const m = manifest(Array.from({ length: 20 }, () => file({ name: '漢'.repeat(1024) })));
    await expect(encryptManifest(generateDropKey(), m)).rejects.toThrow(RangeError);
  });

  it('schema rejection works', async () => {
    const dk = generateDropKey();
    const good = manifest();
    const id = good.files[0].id;
    const cases: [string, unknown][] = [
      ['wrong version', { ...good, v: 2 }],
      ['unknown top-level key', { ...good, extra: true }],
      ['missing note', { v: 1, createdAt: good.createdAt, files: good.files }],
      ['no files', { ...good, files: [] }],
      ['21 files', { ...good, files: Array.from({ length: 21 }, () => file()) }],
      ['chunkCount inconsistent with size', { ...good, files: [file({ size: MiB4 + 1 })] }],
      ['duplicate file ids', { ...good, files: [file({ id }), file({ id })] }],
      ['empty name', { ...good, files: [file({ name: '' })] }],
      ['name over 1024 chars', { ...good, files: [file({ name: 'x'.repeat(1025) })] }],
      ['type over 255 chars', { ...good, files: [file({ type: 't'.repeat(256) })] }],
      ['note over 2000 chars', { ...good, note: 'z'.repeat(2001) }],
      ['negative size', { ...good, files: [file({ size: -1 })] }],
      ['another chunk size', { ...good, files: [file({ chunkSize: 1024 } as never)] }],
      ['non-canonical file id', { ...good, files: [file({ id: `${'A'.repeat(21)}B` })] }],
      ['unknown file key', { ...good, files: [{ ...file(), path: '/home/me' }] }],
    ];
    for (const [label, value] of cases) {
      const forged = await sealRaw(dk, JSON.stringify(value));
      await expect(decryptManifest(dk, forged), label).rejects.toBeInstanceOf(IntegrityError);
      await expect(encryptManifest(dk, value as Manifest), label).rejects.toBeInstanceOf(ZodError);
    }
  });

  it('authenticated bytes that are not UTF-8 JSON → IntegrityError', async () => {
    const dk = generateDropKey();
    for (const plaintext of ['not json', '[]', 'null', new Uint8Array([0xff, 0xfe])]) {
      await expect(decryptManifest(dk, await sealRaw(dk, plaintext))).rejects.toBeInstanceOf(
        IntegrityError,
      );
    }
  });

  it('a tampered, truncated or relabelled blob → IntegrityError', async () => {
    const dk = generateDropKey();
    const m = manifest();
    const raw = Buffer.from(await encryptManifest(dk, m), 'base64url');
    const flipped = Buffer.from(raw);
    flipped[20] ^= 0x01;
    const forgeries = [
      flipped.toString('base64url'),
      raw.subarray(0, raw.length - 1).toString('base64url'),
      raw.subarray(0, 28).toString('base64url'),
      await sealRaw(dk, JSON.stringify(m), 'cipherdrop/v1/chunk'),
    ];
    for (const blob of forgeries) {
      await expect(decryptManifest(dk, blob)).rejects.toBeInstanceOf(IntegrityError);
    }
  });

  it('the wrong drop key → IntegrityError', async () => {
    const blob = await encryptManifest(generateDropKey(), manifest());
    await expect(decryptManifest(generateDropKey(), blob)).rejects.toBeInstanceOf(IntegrityError);
  });

  it('a blob that is not base64url, or is over 64 KiB → IntegrityError', async () => {
    const dk = generateDropKey();
    for (const blob of ['', '***', 'A'.repeat(65_537)]) {
      await expect(decryptManifest(dk, blob)).rejects.toBeInstanceOf(IntegrityError);
    }
  });

  it('a missing blob is a programming error, not an integrity failure', async () => {
    // DropMeta.encryptedManifest is null for password drops: callers must unlock first.
    await expect(decryptManifest(generateDropKey(), null as unknown as string)).rejects.toThrow(
      TypeError,
    );
  });
});
