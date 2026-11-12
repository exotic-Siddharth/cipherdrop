# Benchmarks

Measured on 2026-11-12 on a shared Windows laptop, not on a quiet server. Every number below comes from a run
made for this document; nothing is copied from another machine. Read the caveats before quoting any figure.

Rates are **MiB/s** (1 MiB = 1,048,576 bytes) of plaintext unless a column says otherwise. "Median, min, max"
are over the runs listed in each section; with 3 to 9 runs the spread says more than the median does.

## 1. Machine and software

| Item | Value |
|---|---|
| CPU | 11th Gen Intel Core i7-1195G7, 4 cores / 8 threads, 2.90 GHz base (laptop, on AC power) |
| RAM | 31.7 GB |
| OS | Windows 11 Home 10.0.26300 |
| Node / npm | 22.12.0 / 10.9.0 |
| Browser | Chromium 158.0.8127.18, headless, driven by Playwright 1.65.0 (one browser, one context per run) |
| Web build | Vite 7.3.7 production build (`vite build`), served by `vite preview` with the production security headers and CSP |
| API | Express 5.3.0 started from source with `tsx 4.23.15` (not the production image), local storage driver, Prisma 6 |
| Argon2id | `hash-wasm` 4.13.0 (WebAssembly), in Node for the crypto bench and in a module Worker in the browser |
| Postgres / Redis | `postgres:16-alpine` and `redis:7-alpine` in Docker Desktop 29.9.2 (dev infrastructure containers, host ports 55433 / 56380) |

The API, Vite and the browser run on the host; only Postgres and Redis run in Docker Desktop (a WSL2 VM). Blob
storage is the local driver on the laptop's SSD.

## 2. Method

**Load.** The machine is shared with another user session that sometimes runs heavy jobs (during this session an
`ffmpeg` process at about 150 % CPU of one core appeared). `LoadPercentage` is the output of
`(Get-CimInstance Win32_Processor).LoadPercentage` (an instantaneous reading) taken right before and right after each
benchmark invocation. The idle level of this laptop with the editor and Docker Desktop open was 20 to 40 %.

**Isolation.** The API bench and the browser bench ran against an API of their own on port 4102 (started with
`apps/web/e2e/support/start-api.ts`, which uses the disposable `cipherdrop_e2e` database, Redis DB 9,
`RATE_LIMITS_ENABLED=false`, blobs in `apps/api/data/e2e-blobs`), and the production build was served by `vite
preview` on port 5175 with `API_PROXY_TARGET` pointing at it. Reason: the default rate limits (5 registrations and 30
opens per hour per IP) would stop a benchmark of this size, and the benchmarks must not write into the seeded dev
database. Every bench registers its own throw-away account, deletes its drops, and deletes the account at the end.
One extra API run against the dev API on port 4100 (rate limits on) is in section 4.

**Commands** (repo root; the repo path contains a space, quote it):

```bash
# 1. Crypto in Node (3 invocations)
npm run bench -w @cipherdrop/crypto

# 2. Own API for the benches (rate limits off, disposable e2e database), port 4102
NODE_ENV=development API_PORT=4102 WEB_ORIGIN=http://localhost:5175 \
  DATABASE_URL='postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_e2e?schema=public' \
  REDIS_URL='redis://localhost:56380/9' KEY_PREFIX=cd-bench RATE_LIMITS_ENABLED=false \
  STORAGE_DIR=./data/e2e-blobs STORAGE_DRIVER=local LOG_LEVEL=warn CLEANUP_INTERVAL_SEC=3600 \
  node --import tsx apps/web/e2e/support/start-api.ts

# 3. API upload/download in Node (3 invocations, each: 1 warm-up of 16 MiB, then 3 runs of 96 MiB)
BENCH_API_URL=http://localhost:4102 npm run bench -w @cipherdrop/api

# 4. Production build + vite preview on 5175, proxying /api to the bench API
npm run build -w @cipherdrop/web
API_PROXY_TARGET=http://127.0.0.1:4102 npm run preview -w @cipherdrop/web -- --port 5175 --strictPort

# 5. Browser (3 invocations, each: 1 warm-up of 8 MiB, then 3 runs of 96 MiB, fresh browser context per run)
BENCH_WEB_URL=http://localhost:5175 npm run bench:browser -w @cipherdrop/web

# 6. Control: headless Chromium PUTting to a bare Node server (no CipherDrop code)
npm run bench:ceiling -w @cipherdrop/web
```

**Workload.** 96 MiB (100,663,296 bytes) of random data, 24 chunks of 4 MiB (`CHUNK_SIZE`), signed-in sender,
`maxDownloads` 100 so a run can download several times. Concurrency: the SPA's upload worker keeps 3 chunks in flight,
and the Node bench uses the same 3 (plus a 1-in-flight row). Downloads are in order, with 3 fetches ahead.

**What each row times.**

| Row | Timer starts | Timer stops |
|---|---|---|
| Upload only (Node) | `POST /drops` (ciphertext and `X-Chunk-SHA256` prepared beforehand) | `POST /drops/:id/complete` returns |
| Encrypt + SHA-256 + upload (Node) | same, but AES-256-GCM and SHA-256 of each chunk run inside the timer | same |
| Download only / download + decrypt (Node) | `POST /drops/:id/open` | last chunk fetched (and decrypted, with the in-order STREAM decryptor) |
| Encrypt + upload (browser) | click on "Encrypt & upload" | the success card "Your encrypted link is ready" is visible |
| Download + decrypt (browser) | click on "Decrypt & download" in a fresh context without a session | the browser's `download` event (all chunks fetched and decrypted, file handed over as a Blob) |
| Download + decrypt, incl. page load (browser) | `page.goto(link)` | the same download event |
| Argon2id derive (browser) | the prelogin response arrives | the login request leaves; both are stamped by a wrapper around `fetch` inside the page, so the figure is the Argon2id derive in the kdf Worker plus a worker message round trip |

Integrity is checked outside every timer: the Node bench compares the decrypted bytes with the plaintext, the
browser bench compares the SHA-256 of the file the browser saved with the original. A run with a mismatch aborts
instead of reporting.

**Cold and warm derive.** The first derive in a page includes starting the module Worker and compiling the
`hash-wasm` module ("cold", a fresh context each run). After a client-side sign-out and sign-in in the same page
the worker is reused ("warm", two more derives per run).

## 3. Crypto in Node (`packages/crypto`, single stream, sequential 4 MiB chunks)

3 invocations of `npm run bench -w @cipherdrop/crypto`; each reports the median of 5 passes over 64 MiB (3 for
Argon2id) after a warm-up. Load before to after: 36 to 51 %, 32 to 42 %, 32 to 25 %.

| Operation | Median of 3 | Min | Max |
|---|---:|---:|---:|
| STREAM encrypt (AES-256-GCM) | 846 MiB/s | 773 | 856 |
| STREAM decrypt (in-order decryptor) | 727 MiB/s | 710 | 728 |
| SHA-256 of ciphertext chunks (`X-Chunk-SHA256`) | 592 MiB/s | 557 | 618 |
| Argon2id at `KDF_DEFAULT` (64 MiB, t=3, p=1), hash-wasm in Node | 328 ms | 277 | 341 |
| Argon2id at `KDF_MIN` (19 MiB, t=2, p=1) | 84 ms | 69 | 114 |

Raw output: `npm run bench -w @cipherdrop/crypto` prints this table itself.

## 4. API upload and download in Node (96 MiB, 3 in flight)

3 invocations x 3 runs = 9 runs against the bench API on port 4102 (rate limits off). Load before to after per
invocation: 39 to 45 %, 56 to 35 %, 31 to 35 %.

| Operation | Median of 9 | Min | Max |
|---|---:|---:|---:|
| Upload only, 1 chunk in flight (ciphertext prepared) | 67.0 | 63.6 | 79.8 |
| Upload only, 3 in flight (ciphertext prepared) | 111.5 | 105.2 | 121.2 |
| Encrypt + SHA-256 + upload, 3 in flight | 82.3 | 67.7 | 89.8 |
| Download only, 3 in flight | 134.7 | 93.8 | 150.8 |
| Download + decrypt, 3 in flight | 121.6 | 96.5 | 141.0 |

Two side measurements with the same script:

| Setup | Encrypt + upload | Download + decrypt | Runs, load |
|---|---:|---:|---|
| Dev API on port 4100, **rate limits on** (so Redis counts every chunk) | 79.9 and 82.1 | 102.2 and 127.2 | 2 runs, load 80 to 32 % |
| Through `vite preview` (its `/api` proxy) to the bench API | 108.5 | 104.4 | 1 run, load 29 to 30 % |

These are too few runs to say how much the rate-limit counters or the Vite proxy cost; they only show that neither
is the bottleneck of the browser numbers in section 5.

**Cross-check with the Prometheus metrics (DESIGN section 15).** A separate small run (8 MiB, 1 run after a 16 MiB
warm-up) against the bench API moved `chunk_bytes_uploaded_total` by 75,497,760 bytes and
`chunk_bytes_downloaded_total` by 50,331,840 bytes. The expected values are 72 MiB + 288 B of GCM tags uploaded
(3 uploads each of 16 and 8 MiB) and 48 MiB + 192 B downloaded (2 downloads each): exact match. `drops_created_total`
rose by 6 and `drop_opens_total` by 4, also as expected.

## 5. Browser, production build served by `vite preview` (96 MiB)

Headless Chromium 158, one browser, a fresh context per run, signed-in sender, download in a second fresh context
without a session. Three invocations x 3 runs. The three invocations ran under different machine load, which is
visible in the spread, so each is shown:

| Invocation | Load before to after | Derive cold (ms) | Derive warm (ms) | Encrypt + upload (MiB/s) | Download + decrypt (MiB/s) | Download + decrypt incl. page load |
|---|---|---|---|---|---|---|
| 1 | 48 to 20 % | 257, 373, 291 | 253, 219, 313, 312, 316, 245 | 11.3, 7.5, 9.1 | 50.2, 45.7, 47.0 | 41.4, 38.6, 39.6 |
| 2 | 52 to 17 % | 340, 320, 272 | 447, 407, 290, 250, 241, 258 | 4.8, 13.0, 14.7 | 32.0, 68.3, 68.9 | 26.8, 56.8, 56.6 |
| 3 | 4 to 4 % | 235, 298, 240 | 202, 209, 235, 226, 217, 268 | 15.3, 14.8, 14.9 | 68.1, 73.8, 66.2 | 57.4, 60.5, 55.3 |

Pooled over all 9 runs (18 warm derives):

| Operation | Median | Min | Max |
|---|---:|---:|---:|
| Argon2id derive in the browser Worker, cold (ms) | 291 | 235 | 373 |
| Argon2id derive in the browser Worker, warm (ms) | 253 | 202 | 447 |
| Encrypt + upload, 96 MiB (MiB/s) | 13.0 | 4.8 | 15.3 |
| Download + decrypt, 96 MiB, click to download event (MiB/s) | 66.2 | 32.0 | 73.8 |
| Download + decrypt, 96 MiB, including page load (MiB/s) | 55.3 | 26.8 | 60.5 |

On the quietest invocation (3, load 4 %) the numbers are 14.9 MiB/s up, 68.1 MiB/s down, 240 ms cold derive and
226 ms warm derive. The pooled median is the better summary of what to expect on this laptop on a normal day; the
invocation-3 figures are the best case.

**Contended runs, kept as a warning.** Two further invocations ran while the other user session saturated the CPU
(`LoadPercentage` 100 % before and after, an `ffmpeg` process at about 150 % CPU; they are not in the pooled figures):
derive cold 774 to 1066 ms (median 1007), derive warm 939 to 1348 ms (median 1184), encrypt + upload 4.0 to 5.1 MiB/s
(median 4.6), download + decrypt 9.2 to 19.7 MiB/s (median 13.8). The same code path is 3 to 5 times slower when the
cores are busy, so a benchmark taken on this machine without a load reading means little.

**The upload number is the browser, not the crypto or the API.** The same 96 MiB goes at 82 to 108 MiB/s (encrypt +
upload) from Node to the same API, even through the same Vite proxy (section 4), and the crypto alone does about
850 MiB/s in Node. Chromium itself is the limit here: with no CipherDrop code at all, headless Chromium PUTting 4 MiB
bodies to a bare Node http server that discards them reaches only (3 runs after a warm-up, load 32 to 42 %):

| PUTs in flight | Median MiB/s | Min | Max |
|---:|---:|---:|---:|
| 1 | 20.5 | 19.7 | 20.6 |
| 3 | 17.7 | 17.6 | 19.4 |

So the app's 13.0 to 15.3 MiB/s (invocations 2 and 3) is roughly 70 to 85 % of the most this browser could upload at all
on this machine (the control ran at a different moment and load, so this ratio is approximate). The cause inside Chromium or Windows loopback was not investigated. Download is much faster than
upload in the same browser (66 against 13 MiB/s), which fits a limit on the browser's upload path, and a real browser on a real network will have
different limits; do not read these as the throughput of the design.

## 6. Comparison with the integration measurements

Measured earlier (integration step I1, recorded in the [DESIGN.md](DESIGN.md#decisions-log) Decisions log) on the Vite **dev** server with its proxy, same laptop, load not
recorded:

| Metric | Integration (dev server) | Now (production build, `vite preview`) |
|---|---:|---:|
| Argon2id derive, 64 MiB, t=3, median | 327 ms (warm worker, 5 derives) | 253 ms warm (18 derives), 291 ms cold (9 derives) |
| Encrypt + upload, 96 MB | 12.2 MB/s (one run) | 13.0 MiB/s median of 9 (4.8 to 15.3) |
| Download + decrypt, 96 MB | 27.8 MB/s (one run, including page load) | 55.3 MiB/s including page load (26.8 to 60.5); 66.2 without |

The integration "MB" were computed as 96 divided by seconds, which is MiB/s, so the units agree. Reading the table:

- The derive is in the same range; the production build is slightly faster than the dev server (minified,
  no HMR runtime), within the spread of both.
- Upload is unchanged within noise, consistent with the browser upload ceiling above. A production build does not
  change what Chromium's fetch can push.
- Download roughly doubled. The integration figure was one run on the dev server (unminified bundles, per-module
  loading) under unknown load; the invocation-1 download here (47 MiB/s at 48 % starting load) is closer to it than
  the quiet-machine runs. I did not isolate how much of the gain is the production build and how much is load.

## 7. Caveats

- **Shared laptop.** Another session on the same machine runs heavy jobs; load went from 4 % to 100 % during this
  work and changed the browser numbers by a factor of 3 to 5. Load readings are single snapshots before and after,
  not averages over the run.
- **Windows and Docker Desktop.** Postgres and Redis run in a WSL2 VM behind Docker Desktop's port forwarding. Heavy
  runs leave many sockets in TIME_WAIT on Windows loopback (about 1,700 after a few runs); repeated back-to-back
  invocations then failed with `connect ETIMEDOUT` to `::1`. The invocations in section 5 therefore waited until the
  TIME_WAIT count fell below 60 before starting. This is a property of the test machine, not of CipherDrop.
- **Not the production deployment.** The API ran from source under `tsx` with the local storage driver, not the
  multi-stage image, nginx, MinIO or S3 (docs/DEPLOYMENT.md). `vite preview` proxies `/api` with Node's
  `http-proxy`; nginx would replace that. A production host with a network between client and server would be
  limited by the network instead.
- **Rate limits were off** for the bench API (they would block the benchmark). Section 4 has two single-digit-run
  side measurements with them on; they are not conclusive.
- **Few runs.** 3 invocations of 3 runs each, 9 runs per figure at most; one warm-up each. The minima and maxima
  are given because the spread is wide. No confidence intervals are claimed.
- **One file size and one data type.** 96 MiB of incompressible random data. Small files are dominated by fixed
  costs (two 8 MiB trial transfers measured 3.0 and 4.2 MiB/s end to end, including worker start-up, manifest and
  key wrapping, and the `complete` call; load not recorded). Argon2id memory use (64 MiB) is not measured.
- **Headless Chromium** with Playwright's default flags is not a user's browser; extensions, service workers and
  the real compositor are absent.
- **Timer boundaries.** The browser upload timer includes the app's own pre-upload work (drop key, manifest, owner
  wrap) and the final `complete`; the Node rows do not include key generation.

## 8. Screenshots

`docs/screenshots/` was regenerated on 2026-11-12 against the seeded dev stack (web on port 5174, API on port 4100)
at 1440x900 and, for send, receive and the dashboard, 390x844 mobile, each in light and dark:

- Seeded accounts were only logged into: `dashboard-*` and `settings-*` show the demo account's seeded drops
  (decrypted client-side), `admin-*` the admin console of the seeded admin.
- `send-*`, `receive-*` and `receive-tamper-blocked-*` use anonymous drops created during the capture
  (3 files, 24 MiB, 1 hour expiry, 5 downloads); the seeded drops' download counters were not touched. The tamper
  shot flips one byte of every chunk response with a Playwright route, and the UI blocks the save.
- `send-progress-*` holds the upload mid-flight with a Playwright route that delays every chunk PUT by 2 s, so the
  MB/s shown in those two images is an artefact of the delay and not a measurement.
- `hero.png` is a copy of `receive-light.png`.
