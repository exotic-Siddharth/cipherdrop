/**
 * Save data as a download through a Blob URL + <a download> (CSP-safe; no data: URLs, no new windows).
 * Pass an already sanitised file name (lib/sanitizeFilename.ts, W2) for anything derived from a manifest.
 */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke after the download has started; revoking synchronously can cancel it in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

/** Save UTF-8 text, e.g. the recovery key as a .txt file. */
export function saveTextFile(
  text: string,
  filename: string,
  type = 'text/plain;charset=utf-8',
): void {
  saveBlob(new Blob([text], { type }), filename);
}
