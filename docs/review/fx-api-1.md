## Progress
- [x] C-01 /open shares the unlock failure buckets (with C-07)
- [x] C-07 unlock limiters count failures only
- [x] C-02 quota check and insert serialised per user
- [x] C-04 chunk PUT re-checks status under a drop row lock
- [x] C-05 per-IP chunk limiter
- [x] C-06 EXPIRED drops keep blobs while a grant is live
- [x] C-08 expired UPLOADING drops reject chunks/complete, cleanup frees them
- [x] C-09 S3 handler timeouts, bigger pool, stalled chunk GET aborted

## Notes
- All eight findings fixed with regression tests; full API suite (incl. S3_TEST=1) 212 passed; eslint, prettier, tsc clean.
- C-01/C-07: failure-only (skipSuccessfulRequests) unlockDropIp/unlockDrop limiters, built twice (/unlock, /open for password drops only via async skip) with the same names so both share Redis keys. Trade-off: an attacker spending the per-drop failure budget also locks recipients out for the window.
- C-02: createDrop runs quota check + insert in one tx under SELECT ... FOR UPDATE on the user row.
- C-04/C-08: storeChunk (service.ts) re-checks status/expiry under SELECT ... FOR SHARE on the drop row held across putChunk + upsert; DELETE /me lists drops after marking them DELETED; complete UPDATE requires expiresAt > now; cleanup deletes UPLOADING drops past expiry.
- C-05: chunkIp limiter, 6000/min per IP, in front of the per-token limiters.
- C-06: EXPIRED drops keep blobs until no live grant (cleanup step 4); grantForDownload serves EXPIRED while blobs exist.
- C-09: S3 requestHandler (256 sockets, 5 s connect, 60 s idle socket) and CHUNK_IDLE_TIMEOUT_SEC (default 30) idle abort on chunk GET.
- Cross-area: DESIGN.md (rate-limit table, env table, section 9 grants/expiry, decisions log) not edited.
