import { createDecipheriv, randomBytes as nodeRandomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  deriveFileKey,
  deriveManifestKey,
  generateDropKey,
  generateFileId,
  hashForServer,
  importAesKey,
  sha256,
} from './keys';

const ascii = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const random = (n: number) => new Uint8Array(nodeRandomBytes(n));
const FILE_ID = 'AAECAwQFBgcICQoLDA0ODw';

describe('generateDropKey', () => {
  it('returns 32 fresh random bytes per drop', () => {
    const a = generateDropKey();
    expect(a).toHaveLength(32);
    expect(hex(a)).not.toBe(hex(generateDropKey()));
  });
});

describe('generateFileId', () => {
  it('is the canonical b64url of 16 fresh random bytes', () => {
    const id = generateFileId();
    expect(id).toMatch(/^[A-Za-z0-9_-]{21}[AQgw]$/);
    expect(Buffer.from(id, 'base64url')).toHaveLength(16);
    expect(generateFileId()).not.toBe(id);
  });
});

describe('deriveFileKey / deriveManifestKey', () => {
  it('derive non-extractable AES-256-GCM keys for encrypt and decrypt only', async () => {
    const dk = generateDropKey();
    for (const key of [await deriveFileKey(dk, FILE_ID), await deriveManifestKey(dk)]) {
      expect(key.extractable).toBe(false);
      expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
      expect([...key.usages].sort()).toEqual(['decrypt', 'encrypt']);
    }
  });

  it('reject a drop key that is not 32 bytes', async () => {
    await expect(deriveFileKey(random(31), FILE_ID)).rejects.toThrow(TypeError);
    await expect(deriveManifestKey(random(33))).rejects.toThrow(TypeError);
  });

  it('reject a fileId that is not the canonical b64url of 16 bytes', async () => {
    const dk = generateDropKey();
    for (const id of [
      '',
      'AAAA',
      `${FILE_ID}AA`,
      'AAECAwQFBgcICQoLDA0ODx',
      'AAECAwQFBgcICQoLDA0OD+',
    ]) {
      await expect(deriveFileKey(dk, id), id).rejects.toThrow(TypeError);
    }
  });
});

describe('importAesKey', () => {
  it('imports 32 raw bytes as a non-extractable AES-256-GCM key', async () => {
    const raw = random(32);
    const key = await importAesKey(raw);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    // The key really is `raw`: Node's AES-256-GCM opens what WebCrypto sealed with it.
    const iv = random(12);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, ascii('hello')),
    );
    const decipher = createDecipheriv('aes-256-gcm', raw, iv);
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
    const opened = Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
    expect(opened.toString('utf8')).toBe('hello');
  });

  it('refuses anything but 32 bytes (no silent AES-128 or AES-192)', async () => {
    for (const n of [16, 24, 31, 33])
      await expect(importAesKey(random(n))).rejects.toThrow(TypeError);
  });
});

describe('sha256 / hashForServer', () => {
  it('sha256 matches the FIPS 180-2 vectors', async () => {
    expect(hex(await sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(hex(await sha256(ascii('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('sha256 hashes only the bytes a subarray view covers', async () => {
    expect(hex(await sha256(ascii('xabcx').subarray(1, 4)))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('hashForServer is b64url(SHA-256(authKey))', async () => {
    expect(await hashForServer(new Uint8Array(32))).toBe(
      'Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU',
    );
  });

  it('hashForServer accepts only 32-byte auth keys', async () => {
    await expect(hashForServer(random(16))).rejects.toThrow(TypeError);
  });
});
