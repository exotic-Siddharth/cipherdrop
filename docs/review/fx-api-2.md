## Progress
- [x] C-10 unhandledRejection/uncaughtException handlers
- [x] C-11 production config guard
- [x] C-12 post-commit audit best-effort
- [x] C-14 Report.providedKey nulled on close/purge, served only for OPEN
- [x] C-13 retention: sessions, tokens, audit, reports, scrub deleted drops
- [x] C-15 chunk PUT concurrency cap, idle timeout, anon pending cap
- [x] C-26 report 410 for gone drops
- [x] C-27 single DROP_DELETED on concurrent deletes

## Notes
- All eight fixed with regression tests; full API suite incl. S3_TEST=1: 242 passed; eslint, prettier, tsc clean.
- C-10: lib/fatalHandlers.ts (fatal pino log + exit 1) installed in index.ts, plus a redis ping before createApp (one readable start-up error).
- C-11: production needs COOKIE_SECURE=true, bare-origin WEB_ORIGIN, explicit DATABASE_URL/REDIS_URL/WEB_ORIGIN/TRUST_PROXY (0 = opt-out); .env not loaded under production. Entropy/URL-password checks not added.
- C-12: audit/service.ts recordAfterCommit (log + swallow) used by create/open/complete/delete/report/admin disable.
- C-13: purge wipes password verifier + chunk rows for every purged drop; manifest + ownerWrappedKey for DELETED/anonymous; cleanup step 6 prunes sessions/refresh tokens (7 d), audit events and closed reports (90 d). Drop rows are not hard-deleted.
- C-14: providedKey nulled on resolve and on purge; admin list serves it for OPEN reports only.
- C-15: MAX_CONCURRENT_CHUNK_UPLOADS (64) cap -> 429, CHUNK_UPLOAD_IDLE_TIMEOUT_SEC (30), ANON_TOTAL_PENDING_BYTES (0 = off), storage_free_bytes gauge set by /readyz (not a readiness failure). Per-process cap only.
- Cross-area: DESIGN.md (env table, decisions log), schema indexes for retention scans.
