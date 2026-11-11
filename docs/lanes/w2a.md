# Lane W2a notes (send + receive pipelines)

## Progress

- [x] lib/sanitizeFilename.ts: tests written / implemented / passing
- [x] crypto/uploader.ts (prepareDrop, uploadDropFiles, retryWithBackoff, verifyResume): tests / impl / passing
- [x] workers/upload.worker.ts (message protocol, {code,message} errors): tests / impl / passing
- [x] crypto/sinks.ts + crypto/downloader.ts (DownloadSession): tests / impl / passing
- [x] stores/deviceDrops.ts: tests / impl / passing
- [x] features/send (SendPage, Dropzone, FileList, HexStream, progress, success card, resume, inline unlock)
- [x] features/receive (ReceivePage, every 11.2 state, report dialog, review mode)
- [x] Gate: vitest 78 pass, tsc clean, eslint+prettier clean, vite build OK (2026-11-08)
- [x] Visual check (port 5195, Playwright with mocked /api, 1440x900 + 390x844, light + dark), screenshots reviewed and fixed; server stopped

## Integration needs

- apps/web/src/crypto/kdfClient.ts (lane W1) is still the frozen stub from the scaffold when W2a finished: the password-protected send (createPasswordProtection), the receive password prompt (deriveDropPasswordKeys) and the inline vault unlock on Send (deriveAccountKeys) only work for real once W1 implements it. W2a unit tests mock the module (R1); no browser check of a password drop against a real KDF was possible.
- features/send/components/VaultUnlockInline.tsx re-implements the vault unlock (GET /auth/vault -> kdfClient.deriveAccountKeys -> unwrapKey AAD.WRAP_ACCOUNT -> useVault.setAccountKey) because the unlock page belongs to another lane. If lane W1 or W2b ships a shared unlock helper (stores/vault or features/auth), swap this form to use it so the logic lives in one place.
- Receive page endpoints used and not exercised against the real API (only mocked with schema-valid fixtures): GET /drops/:id, POST /drops/:id/open, POST /drops/:id/unlock, GET chunk, POST /drops/:id/report, POST /admin/drops/:id/grant (review mode, R13). Send: POST /drops, PUT chunks, GET upload-status, POST complete, DELETE /drops/:id. The integration agent should run one real end-to-end send -> receive against the API (including ?review=1 with an admin session and the 409 complete-repair path).
- The upload worker is created with new Worker(new URL('../../workers/upload.worker.ts', import.meta.url), { type: 'module' }) in features/send/uploadClient.ts; verified by vite build and a mocked browser run, but never against a real server: check the production CSP (worker-src 'self') in the nginx or API headers allows module workers from the same origin.
- apps/web/src/routes or router.tsx must keep the lazily loaded ReceivePage at /d/:id (it reads the key from location.hash) and SendPage at the index route; no router change was needed.

## Decisions

- 2026-11-08: Anonymous drops are remembered in localStorage (stores/deviceDrops: dropId, ownerToken, createdAt, expiresAt only); the "Sent from this device" list prunes expired entries on load and removes an entry after a successful Delete.
- 2026-11-08: The resume record lives in sessionStorage (R11) and carries no file names; the resume prompt asks the sender to re-select the same files, matched by size + lastModified, and verifyResume re-encrypts the last received chunk of every file and compares its SHA-256 with upload-status before continuing; any mismatch abandons the old drop (best-effort delete) and starts a fresh one.
- 2026-11-08: Failure taxonomy (R14): network errors, 429 and 5xx are retried 3 times with backoff 0.5 s / 2 s / 8 s (Retry-After honoured, capped), then shown as a retryable error state; only a cryptographic IntegrityError shows the "modified in transit or storage" error and nothing is written.
- 2026-11-08: Files of 256 MB or less are saved through a Blob and a[download]; larger files get a per-file "Save..." button that calls showSaveFilePicker first inside the click handler (R22). Saved names pass through sanitizeFilename (200 unit cap, R15) and the manifest name accepts up to 1024 units.
- 2026-11-08: FileList lays each row out as a grid (icon, name, trailing actions, then a full-width detail row) so per-file progress bars align across rows and previews keep their width on a 390 px screen.
