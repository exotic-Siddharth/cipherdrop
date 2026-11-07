/**
 * The drop manifest (spec section 7.3). It holds every piece of plaintext metadata (names, sizes, types,
 * note) and only ever leaves the browser encrypted:
 *
 * encryptedManifest = b64url(nonce(12 random) || AES-GCM(manifestKey, nonce, aad = "cipherdrop/v1/manifest", utf8(JSON)))
 *
 * ManifestSchema is the normative contract; decryptManifest validates with it after decryption.
 */
import { z } from 'zod';
import {
  AAD,
  CHUNK_SIZE,
  KEY_BYTES,
  MANIFEST_VERSION,
  MAX_ENCRYPTED_MANIFEST_CHARS,
  MAX_FILE_NAME_CHARS,
  MAX_FILE_TYPE_CHARS,
  MAX_FILES_PER_DROP,
  MAX_NOTE_CHARS,
  NONCE_BYTES,
  TAG_BYTES,
} from './constants';
import {
  assertBytes,
  b64urlDecode,
  b64urlEncode,
  randomBytes,
  utf8Decode,
  utf8Encode,
} from './encoding';
import { IntegrityError } from './errors';
import { concatBytes, gcmDecrypt, gcmEncrypt, isAuthFailure } from './internal';
import { deriveManifestKey } from './keys';

const MANIFEST_AAD = utf8Encode(AAD.MANIFEST);

/** Canonical unpadded base64url of exactly 16 bytes (22 chars; the last char carries 2 data bits). */
const FILE_ID_RE = /^[A-Za-z0-9_-]{21}[AQgw]$/;

export const ManifestFileSchema = z
  .object({
    id: z.string().regex(FILE_ID_RE, 'fileId must be b64url(16 bytes)'),
    /** Original name for display, 1..1024 UTF-16 code units (R15). Sanitised only when saving. */
    name: z.string().min(1).max(MAX_FILE_NAME_CHARS),
    size: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    /** MIME type, at most 255 chars, may be "". */
    type: z.string().max(MAX_FILE_TYPE_CHARS),
    lastModified: z.number().int(),
    chunkSize: z.literal(CHUNK_SIZE),
    chunkCount: z.number().int().positive(),
  })
  .strict()
  .superRefine((f, ctx) => {
    const expected = Math.max(1, Math.ceil(f.size / f.chunkSize));
    if (f.chunkCount !== expected) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['chunkCount'],
        message: `chunkCount must be max(1, ceil(size / chunkSize)) = ${expected}`,
      });
    }
  });

export const ManifestSchema = z
  .object({
    v: z.literal(MANIFEST_VERSION),
    /** Milliseconds since the epoch. */
    createdAt: z.number().int().nonnegative(),
    note: z.string().max(MAX_NOTE_CHARS).nullable(),
    files: z
      // Validate at most max+1 elements: zod 3 otherwise parses every element of an oversized array.
      .preprocess(
        (v) =>
          Array.isArray(v) && v.length > MAX_FILES_PER_DROP
            ? v.slice(0, MAX_FILES_PER_DROP + 1)
            : v,
        z.array(ManifestFileSchema).min(1).max(MAX_FILES_PER_DROP),
      )
      .superRefine((files, ctx) => {
        const seen = new Set<string>();
        files.forEach((f, i) => {
          if (seen.has(f.id)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: [i, 'id'],
              message: 'fileId must be unique within the drop',
            });
          }
          seen.add(f.id);
        });
      }),
  })
  .strict();

export type Manifest = z.infer<typeof ManifestSchema>;
export type ManifestFile = z.infer<typeof ManifestFileSchema>;

/**
 * Encrypt a manifest under manifestKey(DK). Result is at most 64 KiB encoded.
 *
 * The manifest is validated first and a ZodError is thrown for an invalid one, which recipients would
 * refuse anyway. A RangeError is thrown when the blob would exceed 64 KiB, which only very long
 * non-ASCII file names or notes can cause; the server would reject such a drop with a 400.
 */
export async function encryptManifest(dk: Uint8Array, m: Manifest): Promise<string> {
  assertBytes(dk, 'dk', KEY_BYTES);
  const manifest = ManifestSchema.parse(m);
  const key = await deriveManifestKey(dk);
  const nonce = randomBytes(NONCE_BYTES);
  const sealed = await gcmEncrypt(key, nonce, MANIFEST_AAD, utf8Encode(JSON.stringify(manifest)));
  const blob = b64urlEncode(concatBytes(nonce, sealed));
  if (blob.length > MAX_ENCRYPTED_MANIFEST_CHARS) {
    throw new RangeError(
      `The encrypted manifest is ${blob.length} characters, above the limit of ` +
        `${MAX_ENCRYPTED_MANIFEST_CHARS}: shorten the file names or the note`,
    );
  }
  return blob;
}

/** Decrypt and zod-validate a manifest. Throws IntegrityError on authentication or schema failure. */
export async function decryptManifest(dk: Uint8Array, blob: string): Promise<Manifest> {
  assertBytes(dk, 'dk', KEY_BYTES);
  // DropMeta.encryptedManifest is null for password drops: a missing blob is a caller bug, not tampering.
  if (typeof blob !== 'string') throw new TypeError('encryptedManifest must be a string');
  if (blob.length > MAX_ENCRYPTED_MANIFEST_CHARS) {
    throw new IntegrityError('The encrypted manifest is larger than 64 KiB');
  }
  let raw: Uint8Array<ArrayBuffer>;
  try {
    raw = b64urlDecode(blob);
  } catch (e) {
    throw new IntegrityError('The encrypted manifest is not valid base64url', { cause: e });
  }
  if (raw.length <= NONCE_BYTES + TAG_BYTES) {
    throw new IntegrityError('The encrypted manifest is too short');
  }
  const key = await deriveManifestKey(dk);
  let plaintext: Uint8Array<ArrayBuffer>;
  try {
    plaintext = await gcmDecrypt(
      key,
      raw.subarray(0, NONCE_BYTES),
      MANIFEST_AAD,
      raw.subarray(NONCE_BYTES),
    );
  } catch (e) {
    if (!isAuthFailure(e)) throw e;
    const reason = 'The manifest failed authentication: it was modified or the key is wrong';
    throw new IntegrityError(reason, { cause: e });
  }
  let json: unknown;
  try {
    json = JSON.parse(utf8Decode(plaintext));
  } catch (e) {
    throw new IntegrityError('The manifest is not UTF-8 JSON', { cause: e });
  }
  const parsed = ManifestSchema.safeParse(json);
  if (!parsed.success) {
    throw new IntegrityError('The manifest does not match the manifest schema', {
      cause: parsed.error,
    });
  }
  return parsed.data;
}
