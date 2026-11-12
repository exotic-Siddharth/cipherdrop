# Two-minute demo

A live demo script for the local dev stack: what to click, in order, and what to say. It uses the seed data
from `npm run db:seed` (see the [README quick start](../README.md#quick-start)).

## Before you start

- Stack running: `docker compose up -d --wait`, then `npm run dev` (web on http://localhost:5174, API on port 4100).
- `apps/web/.env` contains `VITE_DEMO_CREDENTIALS` (copied from `apps/web/.env.example`), so the login page shows
  **Use demo account**.
- Seed accounts (dev only, passwords from `apps/api/.env`):

  | Account | Password (example default) | Role |
  |---|---|---|
  | `demo@cipherdrop.local` | `SEED_DEMO_PASSWORD`, `demo-cipherdrop-dev-2026` | user, owns the seeded drops |
  | `admin@cipherdrop.local` | `SEED_ADMIN_PASSWORD`, `admin-cipherdrop-dev-2026` | admin |

- Re-run `npm run db:seed`: it creates nothing new and reprints the share links. Keep the link of
  **diagram.png (password-protected)** at hand; its password is `correct horse battery staple`.
- The seeded drops expire 1 day (burn-note.txt), 3 days (diagram.png) and 7 days (welcome.txt + sample.csv) after
  the **first** seed run, and re-running the seed does not renew them. If they have expired, use a drop you send
  during the demo instead, or rebuild the dev database by hand with `npm run db:reset && npm run db:seed` (this
  deletes all dev data).
- Have a normal window and a private window side by side. Prepare a small image file to send.

## Script

| Time | Click | Say |
|---|---|---|
| 0:00 | Normal window, **Send** page (`/`). Drop the image. Set **Download limit** to **1 — burn after reading**, add a note. | "CipherDrop is end-to-end encrypted file sharing. The server never encrypts or decrypts anything: the browser encrypts each file with AES-256-GCM before it leaves the machine." |
| 0:15 | **Encrypt & upload**. Point at the moving hex strip. | "These are the real ciphertext bytes of the chunk just encrypted. Files go up in 4 MiB chunks; each chunk's nonce holds its position and a last-chunk flag, so reordering or cutting the file is detected." |
| 0:25 | Success card: point at the part of the link after `#`. | "The key is in the fragment. Browsers never send the fragment to a server, so the server stores only ciphertext and cannot read the file, its name or the note." |
| 0:35 | Copy the link, paste it into the private window. The receive page shows the file name and note. | "The name and the note were encrypted too. They were decrypted here, with the key from the link." |
| 0:45 | **Decrypt & download**, confirm **Download now** in the "last download" dialog. Show **Integrity verified** and the preview. | "Every chunk is authenticated while it streams in. If one byte had changed in transit or in storage, the page would block the save; an automated Playwright test does exactly that." |
| 0:55 | Reload the private window. | "It was burn after reading: the server consumed the only download with one atomic database update. In the integration test, 10 concurrent opens give exactly one success." |
| 1:05 | Private window: open the **diagram.png** link. Type a wrong password, then `correct horse battery staple`. | "This link carries no key. The password goes through Argon2id in a Web Worker; the server only checks a hash of a derived key and releases the wrapped drop key, with rate limits on failures." |
| 1:20 | Normal window: **Log in** in the header, then **Use demo account** (it fills in the form) and **Log in**. The dashboard lists the active seeded drops with their names and statuses; the **All** tab adds the expired one. | "Accounts are zero-knowledge too. The password never leaves the browser; it unwraps an account key, which unwraps each drop key, so the dashboard decrypts names on any device." |
| 1:35 | Reload the dashboard. The vault is locked; enter the demo password on **Unlock**. | "The session survives a reload, but the key lives only in memory, so the vault locks. The unlock is checked locally, without a request." |
| 1:45 | **Settings**, **Activity** tab. | "The audit log shows that a drop was opened, by IP prefix and browser only, never the full address." |
| 1:55 | **How it works**, scroll to **Honest limitations**, click the `docs/SECURITY.md` link. | "And the limits are written down: the server sees sizes and timing, and browser crypto trusts the JavaScript the server delivers. The threat model covers each adversary." |

## If you have another minute

- **Admin.** Sign out, log in as `admin@cipherdrop.local`, open **Admin**. The reports queue holds one seeded
  report on diagram.png with the reporter's key attached. **Review** opens it without consuming a download and
  writes an `ADMIN_REVIEW_GRANT` audit event; **Disable** deletes its blobs. Review is refused once the drop has
  expired (an accepted open point in [SECURITY.md](SECURITY.md#7-accepted-open-points)).
- **Tamper evidence.** Show `docs/screenshots/receive-tamper-blocked-light.png`, captured by flipping one byte of
  every chunk response with a Playwright route, or run `npm run e2e` and point at test 4 in
  `apps/web/e2e/drops.spec.ts`.
- **API.** Open http://localhost:5174/api/docs (Swagger UI) and show that `POST /drops` takes only an encrypted
  manifest, sizes and options.
- **Network tab.** In the browser's developer tools, filter on `/api/drops` during an upload: the request bodies
  are base64url blobs and raw ciphertext, and no request contains the file name.

## Questions to expect

- *Can the server read files if it is malicious?* Not from what it stores. It could serve modified JavaScript;
  see [SECURITY.md section 2.1](SECURITY.md#21-the-server-operator-or-anyone-who-controls-the-server).
- *What happens if I forget my password?* The recovery key resets it. Without both, the data is lost by design.
- *How fast is it?* See [BENCHMARKS.md](BENCHMARKS.md): 13.0 MiB/s encrypt and upload and 66.2 MiB/s download
  and decrypt (medians, headless Chromium, 96 MiB, on a 4-core laptop), where the upload figure is roughly 70 to 85 %
  of what headless Chromium itself uploads on that machine with no CipherDrop code.
