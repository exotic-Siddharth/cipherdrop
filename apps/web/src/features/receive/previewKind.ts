/** Raster formats only: SVG can carry script, so it is never previewed (spec 11.2). */
const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
const TEXT_PREVIEW_MAX_BYTES = 1024 * 1024;

export function previewKind(type: string, size: number): 'image' | 'text' | null {
  const t = type.toLowerCase();
  if (IMAGE_TYPES.has(t)) return 'image';
  if (size <= TEXT_PREVIEW_MAX_BYTES && (t.startsWith('text/') || t === 'application/json'))
    return 'text';
  return null;
}
