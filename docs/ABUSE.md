# Abuse handling

How an operator of a CipherDrop instance handles abuse. CipherDrop is end-to-end encrypted: the server stores
ciphertext and never sees a drop key unless a reporter chooses to attach one. This page says what that leaves an
operator able to do. See [SECURITY.md](SECURITY.md) for the threat model and [DEPLOYMENT.md](DEPLOYMENT.md) for
the operator commands.

## Intake

- **Reports.** Every receive page has a Report link. A report names a reason and may carry the drop key, only if
  the reporter ticks the box. It lands in the admin console's report queue.
- **Notices from outside** (an email to the abuse contact, a takedown notice). They need no report: an admin takes
  the drop down by link or id in the console's "Take a drop down" card, or the operator runs
  `node dist/cli.js drop:disable <dropId> --reason "<notice reference>"`. Only the part of a link before `#` is
  used; the key after it is cut off before anything is sent.

## Triage

1. A report with the key can be reviewed: Review opens the drop in the browser with a non-consuming admin grant
   (it does not count as a download), audited as `ADMIN_REVIEW_GRANT`.
2. A report without the key cannot be reviewed by anyone: the server holds only ciphertext. Decide on the
   report's reason, its details and the account behind the drop.
3. **Disable** the drop (recipients get 410 at once, its blobs are deleted, every open report of it is
   resolved), or **Dismiss** the report. Both erase the attached key.
4. For repeat abuse, **suspend** the account (Users, Suspend, with a reason): every session is signed out at once
   and sign-in is refused until an admin lifts it. Its drops are not touched; take them down one by one. Admins
   are not suspended: remove the role first.

## Evidence hold

While a report that carries the key is open, cleanup does not delete the blobs of the drop when it expires or
runs out of downloads, so the review stays possible. The hold ends when the report is resolved, or
`REPORT_EVIDENCE_HOLD_DAYS` (default 14, 0 = none) after the report, whichever comes first. An owner's delete and
a takedown are never held: they delete the blobs at once and erase the key.

When an account is deleted, its drops and blobs go as before, but a drop that has reports is kept as an ownerless
row (no blobs, the key erased) so its reports stay in the admin queue.

## What an operator can disclose

On a valid legal request, the server can hand over: the ciphertext (while it is stored), the drop's metadata
(sizes, times, download counts), the coarse IP prefix (IPv4 /24, IPv6 /48) and browser summary of events, and an
account's email. It cannot hand over file names, contents or keys: it never had them, except a key a reporter
attached to a still-open report.

## Accountability

Every admin and operator action (role and quota edits, suspensions, takedowns, dismissals, review grants, session
revocations) is one audit event naming the acting admin, or "operator" for the command line. The console's Audit
card and `node dist/cli.js audit:tail` show them. They are kept for a year, other audit events for 90 days.
