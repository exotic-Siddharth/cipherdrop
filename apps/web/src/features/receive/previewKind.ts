/**
 * How a verified file may be previewed (spec 11.2). The type is the sender's claim, so it only selects the
 * renderer and never reaches the page as markup:
 * - 'image': raster formats only, decoded by an <img> (no script runs in an image). SVG can carry script and is
 *   never previewed. The preview URL is made with this allowlisted type, not with the Blob's own type.
 * - 'text': UTF-8 text in a <pre> as a React text node, so HTML, XML or SVG source shows as source, never as a
 *   document.
 */
const IMAGE_TYPES: ReadonlySet<string> = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
]);
const TEXT_PREVIEW_MAX_BYTES = 1024 * 1024;

export type PreviewKind = { kind: 'image'; type: string } | { kind: 'text' } | null;

export function previewKind(type: string, size: number): PreviewKind {
  const t = type.toLowerCase();
  if (IMAGE_TYPES.has(t)) return { kind: 'image', type: t };
  if (size <= TEXT_PREVIEW_MAX_BYTES && (t.startsWith('text/') || t === 'application/json'))
    return { kind: 'text' };
  return null;
}
