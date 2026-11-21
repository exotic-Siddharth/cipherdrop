# Two-minute demo

A live demo script for the local dev stack: what to click, in order, and what to say. It uses the seed data
from `npm run db:seed` (see the [README quick start](../README.md#quick-start)).

To watch it without running anything, open [screenshots/demo.gif](screenshots/demo.gif) (about 90 seconds, the
same flow with captions) or the [screenshots](../README.md#screenshots). Both are recorded from the real app by
`npm run media -w @cipherdrop/web` ([Recording the demo and the screenshots](#recording-the-demo-and-the-screenshots)).

## Before you start

- Stack running: `docker compose up -d --wait`, then `npm run dev` (web on http://localhost:5174, API on port 4100).
- `apps/web/.env` contains `VITE_DEMO_CREDENTIALS` (copied from `apps/web/.env.example`), so the login page shows
  **Use demo account**.
- `apps/api/.env` contains `API_DOCS_UI=true` (copied from `apps/api/.env.example`) for the Swagger UI beat; an older
  copy needs the line added. Production never serves Swagger UI.
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
| 0:35 | Copy the link, paste it into the private window. The receive page shows the file name and note. | "The name and the note were encrypted too. They were decrypted here, with the key from the link." Optional: point at the address bar. "The page has already taken the key out of it, so it is not on a shared screen; a reload of this tab still opens the drop." |
| 0:45 | **Decrypt & download**, confirm **Download now** in the "last download" dialog. Show **Integrity verified** and the preview. | "Every chunk is authenticated while it streams in. If one byte had changed in transit or in storage, the page would block the save; an automated Playwright test does exactly that." |
| 0:55 | Reload the private window. | "It was burn after reading: the server consumed the only download with one atomic database update. In the integration test, 10 concurrent opens give exactly one success." |
| 1:05 | Private window: open the **diagram.png** link. Type a wrong password, then `correct horse battery staple`. | "This link carries no key. The password goes through Argon2id in a Web Worker; the server only checks a hash of a derived key and releases the wrapped drop key, with rate limits on failures." |
| 1:20 | Normal window: **Log in** in the header, then **Use demo account** (it fills in the form) and **Log in**. The dashboard lists the active seeded drops with their names and statuses; the **All** tab adds the expired one. | "Accounts are zero-knowledge too. The password never leaves the browser; it unwraps an account key, which unwraps each drop key, so the dashboard decrypts names on any device." |
| 1:35 | Reload the dashboard. The vault is locked; enter the demo password on **Unlock**. | "The session survives a reload, but the key lives only in memory, so the vault locks. The unlock is checked locally, without a request." |
| 1:45 | **Settings**, **Activity** tab. | "The audit log shows that a drop was opened, by IP prefix and browser only, never the full address." |
| 1:55 | **How it works**, scroll to **Honest limitations**, click the `docs/SECURITY.md` link. | "And the limits are written down: the server sees sizes and timing, and browser crypto trusts the JavaScript the server delivers. The threat model covers each adversary." |

## If you have another minute

- **Admin.** Sign out, log in as `admin@cipherdrop.local` and open **Admin**: the console first asks for two-step
  verification. Open **Settings**, **Security**, set up two-step verification, scan the QR code, enter the password
  and the code (other signed-in devices are then signed out), save the backup codes, then open **Admin**. Say: "The
  console can reveal reporters' keys, so admins must have two-step verification. Only accounts with it can be
  promoted, admins cannot turn it off, and turning it on ends every session opened with the password alone. The
  seeded demo admin starts without it, which is the one state where knowing the password is enough, so enrol
  first." The reports queue holds one seeded report on diagram.png with the reporter's key attached. **Review**
  opens it without consuming a download and writes an `ADMIN_REVIEW_GRANT` audit event; **Disable** deletes its
  blobs. Review is refused once the drop has expired (an accepted open point in
  [SECURITY.md](SECURITY.md#7-accepted-open-points)). In **Users**, try to make `demo@cipherdrop.local` an admin: it
  is refused, because that account has no two-step verification.
- **Tamper evidence.** Show [screenshots/receive-tamper-blocked-light.png](screenshots/receive-tamper-blocked-light.png)
  (or the phone version, `receive-tamper-blocked-mobile-light.png`), which the media run captures by flipping one byte
  of every chunk response with a Playwright route, as test 4 in `apps/web/e2e/drops.spec.ts` does; the GIF shows the
  same moment. Or run `npm run e2e` and point at that test.
- **API.** Open http://localhost:5174/api/docs (Swagger UI) and show that `POST /drops` takes only an encrypted
  manifest, sizes and options.
- **Network tab.** In the browser's developer tools, filter on `/api/drops` during an upload: the request bodies
  are base64url blobs and raw ciphertext, and no request contains the file name.

## Recording the demo and the screenshots

`npm run media -w @cipherdrop/web` records the script above on video, turns it into `docs/screenshots/demo.gif`, and
regenerates every PNG in `docs/screenshots`. It is opt-in: `npm run e2e` and CI never run it, because it writes into
the repository.

- **Needs** the Compose Postgres and Redis (`docker compose up -d --wait`), Playwright's Chromium and its video
  recorder (`npm run e2e:install -w @cipherdrop/web`), and `ffmpeg` on the `PATH` for the GIF. Without `ffmpeg` the
  screenshots are still made and the recorded scenes stay in `apps/web/test-results/media-video`.
- **Runs** like `npm run e2e` (`apps/web/playwright.media.config.ts`, specs `apps/web/e2e/*.media.ts`): it builds the
  SPA, serves it with `vite preview` under the production CSP, starts the API on the wiped `cipherdrop_e2e` database
  and the e2e ports, so it cannot run at the same time as an e2e run. It seeds that database with
  `apps/api/prisma/seed.ts`, with random passwords for the demo and admin accounts (never the `.env` ones), and creates
  the rest through the UI. Each browser's clock is frozen (`page.clock`), so countdowns read the same in every
  picture, and the e2e leak guard stays on: no file name, note, password or link key may appear in any request.
- **Screenshots** are 1440x900 (desktop) and 390x844 (phone) CSS pixels at device scale factor 2, in light and dark
  where both exist. `send-progress-*` parks the chunk uploads after the fifth, so its MB/s and time left describe a
  stalled upload, not a measurement. `hero.png` is the dark upload view and the light receive view side by side, at
  1280x640.
- **The GIF** is about 90 seconds at 960 px wide and 8 frames per second, under 6 MB (the run fails above that). The
  captions are added to the page for the recording, and each chunk upload is delayed by 600 ms so the ciphertext strip
  stays on screen, so the speed shown in the clip is not a measurement either.
- **Before committing**, look at the pictures. They show dev data only: the seeded accounts, throwaway drops, a
  recovery key and a TOTP secret of accounts in the disposable e2e database, and links to `localhost`; passwords are
  masked. The committed PNGs were then recompressed losslessly with [oxipng](https://github.com/shssoichiro/oxipng)
  at level 4 with safe chunk stripping, through its Python binding `pyoxipng` (the command-line equivalent is
  `oxipng -o 4 --strip safe docs/screenshots/*.png`): the same pixels in about a quarter fewer bytes. The run itself
  writes Playwright's PNGs as they are.

## Questions to expect

- *Can the server read files if it is malicious?* Not from what it stores. It could serve modified JavaScript;
  see [SECURITY.md section 2.1](SECURITY.md#21-the-server-operator-or-anyone-who-controls-the-server).
- *What happens if I forget my password?* The recovery key resets it. Without both, the data is lost by design.
- *How fast is it?* See [BENCHMARKS.md](BENCHMARKS.md): 13.0 MiB/s encrypt and upload and 66.2 MiB/s download
  and decrypt (medians, headless Chromium, 96 MiB, on a 4-core laptop), where the upload figure is roughly 70 to 85 %
  of what headless Chromium itself uploads on that machine with no CipherDrop code.
- *How does the recipient know it's from me?* They don't, from the link alone: anyone can create a drop, and
  "Integrity verified" means the bytes are exactly what was encrypted with the link's key, not who sent them or that
  they are safe. The page says so, and labels the note as not verified. Signatures would need a way to distribute
  and trust public keys, which is out of scope; confirm an unexpected link through another channel
  ([SECURITY.md section 2.6](SECURITY.md#26-sender-identity)).
- *Is it quantum-safe?* What is stored uses only symmetric primitives (AES-256-GCM, HKDF-SHA-256, Argon2id), which
  keep about 128-bit security against Grover's algorithm, and a link's key never reaches the server. The TLS key
  exchange is the terminator's: the bundled Caddy negotiates the X25519MLKEM768 hybrid by default
  ([SECURITY.md section 3](SECURITY.md#3-cryptographic-design-in-brief)).
- *Is AES-GCM key-committing?* No. One ciphertext can be built to decrypt validly under two keys, so a sender could
  make one drop show different content under two links. It gives an attacker nothing against the keys here, and the
  fix (a key commitment checked before decrypting) is written down as future work
  ([packages/crypto/README.md](../packages/crypto/README.md), Limits).
