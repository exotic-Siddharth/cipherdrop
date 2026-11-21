import { useEffect, useState } from 'react';
import { previewKind } from '../previewKind';

export interface FilePreviewProps {
  blob: Blob;
  /** The manifest type (the sender's claim). The saved Blob may carry application/octet-stream instead (sinks.ts). */
  type: string;
  name: string;
}

/** Image or text preview of a decrypted, verified Blob. Text is rendered as text, never as HTML. */
export function FilePreview({ blob, type, name }: FilePreviewProps) {
  const preview = previewKind(type, blob.size);
  const kind = preview?.kind ?? null;
  // The image URL gets the allowlisted raster type, whatever type the Blob itself carries.
  const imageType = preview?.kind === 'image' ? preview.type : null;
  const [url, setUrl] = useState<string | null>(null);
  const [text, setText] = useState<string | null>(null);

  useEffect(() => {
    if (!imageType) return;
    const u = URL.createObjectURL(blob.slice(0, blob.size, imageType));
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [blob, imageType]);

  useEffect(() => {
    if (kind !== 'text') return;
    let alive = true;
    blob
      .text()
      .then((t) => alive && setText(t))
      .catch(() => alive && setText(null));
    return () => {
      alive = false;
    };
  }, [blob, kind]);

  if (kind === 'image' && url) {
    return (
      <div className="mt-2 overflow-hidden rounded-md border border-border bg-surface-2/60">
        <img
          src={url}
          alt={`Preview of ${name}`}
          className="mx-auto max-h-72 w-auto object-contain"
          decoding="async"
        />
      </div>
    );
  }
  if (kind === 'text' && text !== null) {
    return (
      <pre
        className="mt-2 max-h-56 overflow-auto rounded-md border border-border bg-surface-2/60 p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap text-foreground"
        aria-label={`Preview of ${name}`}
        tabIndex={0}
      >
        {text}
      </pre>
    );
  }
  return null;
}
