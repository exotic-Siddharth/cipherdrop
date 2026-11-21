# Security policy

CipherDrop is a zero-knowledge, end-to-end encrypted file-sharing app, built as a portfolio project. Reports of
vulnerabilities are welcome. There is no bug bounty.

The threat model, what the server can and cannot see, and the open points accepted on purpose are in
[docs/SECURITY.md](../docs/SECURITY.md).

## Supported versions

Only the latest commit on `main` is supported. There are no releases or maintenance branches: fixes land on `main`.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/exotic-Siddharth/cipherdrop/security/advisories/new)** (the
Security tab of this repository). Please do not open a public issue, pull request or discussion about it.

The form exists only while the repository's private vulnerability reporting setting is on. As of 2026-11-21 it was
not yet on (docs/SECURITY.md section 7, accepted open points).

A useful report names:

- the commit you tested, and the component (web app, API, `packages/crypto`, deployment files);
- the steps to reproduce it, or a proof of concept against your own instance;
- what an attacker gains, and which of the adversaries in docs/SECURITY.md section 2 you assume.

## What happens next

- The maintainer aims to acknowledge a report within 7 days and to give a first assessment within 14 days.
- The fix is developed in a private security advisory, where you can follow and review it if you want.
- The advisory is published once the fix is on `main`, or 90 days after the report, whichever comes first, unless
  you and the maintainer agree on another date. You are credited in it, unless you prefer not to be.

## Scope

In scope: the code and configuration in this repository, that is the SPA (`apps/web`), the API (`apps/api`),
`packages/crypto`, `packages/shared`, `docker-compose.prod.yml` and `deploy/`. Of most interest:

- anything that lets the server, the network or a holder of the link learn plaintext, a file name or a key that
  docs/SECURITY.md says it cannot learn;
- ways around authentication, two-factor authentication, session revocation, rate limits or the per-client caps;
- ciphertext or metadata that outlives an expiry, burn after reading, "Delete now" or account deletion;
- cross-site scripting, or anything else that runs code on the app's origin, which holds the keys.

Out of scope:

- the accepted open points in docs/SECURITY.md section 7, unless you find a way past the mitigation stated there;
- denial of service by volume, and findings that need a compromised device, browser or extension;
- missing hardening without a demonstrated impact;
- vulnerabilities in dependencies with no exploitable path in CipherDrop (report those upstream);
- instances run by other people. Report a problem with an instance to its operator: its contact is in
  `/.well-known/security.txt` on that instance. If that file points back to this repository, its operator has not
  named a contact of their own: report problems in the code here, and problems specific to that deployment to its
  operator through the site itself.

## Testing and safe harbour

- Test against an instance you run yourself (`docker-compose.yml` for development, `docker-compose.prod.yml` for
  the production stack). Do not test against deployments you do not own, and do not run scanners against them.
- Do not access, change or delete data that is not yours, and keep the details confidential until the advisory is
  published.

If you make a good-faith effort to follow this policy, the maintainer will not take or support legal action against
you for your research, and will say so if anyone asks.

## For operators

Each instance serves `/.well-known/security.txt` (RFC 9116). It points at this repository unless you set your own
contact with `SECURITY_TXT_CONTACT` (and `SECURITY_TXT_POLICY`) when you build the web image: see
`.env.production.example`.
