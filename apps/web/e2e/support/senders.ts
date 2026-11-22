/**
 * A sender in Node: drops encrypted with @cipherdrop/crypto and uploaded through the same /api the SPA uses (POST
 * /drops, the chunk PUTs, complete), for receive-side cases the browser cannot produce cheaply.
 *
 * The server never sees the manifest (spec section 8): the file sizes in it are the sender's claim, and they are
 * exactly what the receive page decides from before it calls /open (C-03). `declaredSize` therefore lets a test
 * claim a 300 MiB file while uploading a few bytes: the refusal it checks happens before a single chunk is fetched.
 * These requests go through Playwright's APIRequestContext, not a page, so the leak guard does not see them.
 */
import {
  buildShareLink,
  CHUNK_SIZE,
  chunkCount,
  deriveFileKey,
  encryptChunk,
  encryptManifest,
  generateDropKey,
  generateFileId,
  sha256,
  toHex,
  type Manifest,
} from '@cipherdrop/crypto';
import {
  CreateDropResponseSchema,
  type CreateDropRequest,
  type DownloadOption,
} from '@cipherdrop/shared';
import { expect, type APIRequestContext } from '@playwright/test';

export interface NodeDropFile {
  name: string;
  type: string;
  /** The plaintext actually encrypted and uploaded (one chunk, so at most 4 MiB). */
  content: Buffer;
  /** The size the manifest declares; defaults to content.length. */
  declaredSize?: number;
}

export interface NodeDrop {
  dropId: string;
  /** The share link, key in the fragment. */
  link: string;
  /** base64url of the drop key, as the link carries it. */
  key: string;
}

/** Encrypt, create, upload and complete an anonymous key-link drop. Each file uploads as a single chunk. */
export async function sendFromNode(
  request: APIRequestContext,
  baseURL: string,
  files: NodeDropFile[],
  opts: { maxDownloads: DownloadOption; expiresInHours?: number; note?: string },
): Promise<NodeDrop> {
  const dk = generateDropKey();
  const now = Date.now();
  const prepared = await Promise.all(
    files.map(async (f) => {
      expect(f.content.length, 'one chunk per file').toBeLessThanOrEqual(CHUNK_SIZE);
      const id = generateFileId();
      const ciphertext = await encryptChunk(
        await deriveFileKey(dk, id),
        0,
        true,
        new Uint8Array(f.content),
      );
      const size = f.declaredSize ?? f.content.length;
      return { f, id, size, ciphertext };
    }),
  );
  const manifest: Manifest = {
    v: 1,
    createdAt: now,
    note: opts.note ?? null,
    files: prepared.map(({ f, id, size }) => ({
      id,
      name: f.name,
      size,
      type: f.type,
      lastModified: now,
      chunkSize: CHUNK_SIZE,
      chunkCount: chunkCount(size),
    })),
  };
  const body: CreateDropRequest = {
    encryptedManifest: await encryptManifest(dk, manifest),
    // What the server stores: one uploaded chunk per file, whatever the manifest claims.
    files: prepared.map(({ id, ciphertext }) => ({
      id,
      ciphertextBytes: ciphertext.length,
      chunkCount: 1,
    })),
    expiresInHours: opts.expiresInHours ?? 1,
    maxDownloads: opts.maxDownloads,
  };

  const created = await request.post('/api/drops', { data: body });
  expect(created.status(), await created.text()).toBe(201);
  const drop = CreateDropResponseSchema.parse(await created.json());
  const auth = { Authorization: `Bearer ${drop.uploadToken}` };
  for (const { id, ciphertext } of prepared) {
    const put = await request.put(`/api/drops/${drop.dropId}/files/${id}/chunks/0`, {
      data: Buffer.from(ciphertext),
      headers: {
        ...auth,
        'Content-Type': 'application/octet-stream',
        'X-Chunk-SHA256': toHex(await sha256(ciphertext)),
      },
    });
    expect(put.status(), await put.text()).toBe(204);
  }
  const done = await request.post(`/api/drops/${drop.dropId}/complete`, { headers: auth });
  expect(done.status(), await done.text()).toBe(200);

  const link = buildShareLink(baseURL, drop.dropId, dk);
  return { dropId: drop.dropId, link, key: new URL(link).hash.slice(1) };
}
