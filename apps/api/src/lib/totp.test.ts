import { Secret, TOTP, URI } from 'otpauth';
import { describe, expect, it } from 'vitest';
import {
  decryptTotpSecret,
  encryptTotpSecret,
  generateTotpSecret,
  matchTotpStep,
  totpOtpauthUrl,
  verifyTotp,
} from './totp';

/** RFC 6238 appendix B: the ASCII secret "12345678901234567890" (SHA-1), as base32. */
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const at = (unixSeconds: number) => new Date(unixSeconds * 1000);

const KEY_A = Buffer.alloc(32, 7).toString('base64');
const KEY_B = Buffer.alloc(32, 9).toString('base64');

/** An independent code generator (otpauth with explicit spec parameters), not the code under test. */
const codeAt = (secret: string, unixSeconds: number) =>
  TOTP.generate({
    secret: Secret.fromBase32(secret),
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    timestamp: unixSeconds * 1000,
  });

describe('lib/totp: code verification', () => {
  it('matches the RFC 6238 SHA-1 vectors (6 digits, 30 s steps) and returns the step', () => {
    // 8-digit RFC values truncated to their last 6 digits (the code is the HOTP value mod 10^6).
    expect(matchTotpStep(RFC_SECRET, '287082', { now: at(59) })).toBe(1);
    expect(matchTotpStep(RFC_SECRET, '081804', { now: at(1111111109) })).toBe(37037036);
    expect(matchTotpStep(RFC_SECRET, '050471', { now: at(1111111111) })).toBe(37037037);
    expect(matchTotpStep(RFC_SECRET, '005924', { now: at(1234567890) })).toBe(41152263);
    expect(matchTotpStep(RFC_SECRET, '279037', { now: at(2000000000) })).toBe(66666666);
  });

  it('accepts exactly one step of drift either way', () => {
    const now = 1111111111; // step 37037037, code 050471
    expect(matchTotpStep(RFC_SECRET, '081804', { now: at(now) })).toBe(37037036); // previous step
    expect(matchTotpStep(RFC_SECRET, '050471', { now: at(now - 30) })).toBe(37037037); // next step
    expect(matchTotpStep(RFC_SECRET, '050471', { now: at(now + 60) })).toBeNull(); // two steps late
    expect(matchTotpStep(RFC_SECRET, '050471', { now: at(now - 60) })).toBeNull(); // two steps early
  });

  it('rejects a code whose step is at or before afterStep (replay protection)', () => {
    const now = at(1111111111);
    expect(matchTotpStep(RFC_SECRET, '050471', { now, afterStep: 37037037 })).toBeNull();
    expect(matchTotpStep(RFC_SECRET, '050471', { now, afterStep: 37037038 })).toBeNull();
    expect(matchTotpStep(RFC_SECRET, '050471', { now, afterStep: 37037036 })).toBe(37037037);
    expect(matchTotpStep(RFC_SECRET, '050471', { now, afterStep: null })).toBe(37037037);
  });

  it('rejects malformed codes', () => {
    const now = at(1111111111);
    for (const code of ['', '05047', '0504711', '05047a', ' 050471', '050 471', '14050471']) {
      expect(matchTotpStep(RFC_SECRET, code, { now }), JSON.stringify(code)).toBeNull();
    }
  });

  it('generateTotpSecret returns distinct 160-bit base32 secrets', () => {
    const a = generateTotpSecret();
    const b = generateTotpSecret();
    expect(a).toMatch(/^[A-Z2-7]{32}$/);
    expect(Secret.fromBase32(a).bytes.length).toBe(20);
    expect(a).not.toBe(b);
  });

  it('totpOtpauthUrl encodes the issuer, the account, SHA1, 6 digits and 30 s', () => {
    const secret = generateTotpSecret();
    const url = totpOtpauthUrl(secret, 'alice@example.com');
    expect(url.startsWith('otpauth://totp/')).toBe(true);
    const parsed = URI.parse(url);
    expect(parsed).toBeInstanceOf(TOTP);
    const totp = parsed as TOTP;
    expect(totp.issuer).toBe('CipherDrop');
    expect(totp.label).toBe('alice@example.com');
    expect(totp.algorithm).toBe('SHA1');
    expect(totp.digits).toBe(6);
    expect(totp.period).toBe(30);
    expect(totp.secret.base32).toBe(secret);
  });
});

describe('lib/totp: secrets at rest (AES-256-GCM, TOTP_ENC_KEY)', () => {
  it('round-trips, uses a fresh nonce every time and never contains the secret', () => {
    const secret = generateTotpSecret();
    const one = encryptTotpSecret(secret, 'user-1', KEY_A);
    const two = encryptTotpSecret(secret, 'user-1', KEY_A);
    expect(one).not.toBe(two);
    for (const blob of [one, two]) {
      expect(blob).not.toContain(secret);
      expect(blob.toLowerCase()).not.toContain(secret.toLowerCase().slice(0, 8));
      expect(decryptTotpSecret(blob, 'user-1', KEY_A)).toBe(secret);
    }
  });

  it('refuses another user id, another key and any tampering, without echoing the secret', () => {
    const secret = generateTotpSecret();
    const blob = encryptTotpSecret(secret, 'user-1', KEY_A);
    const flipped = (() => {
      const body = Buffer.from(blob.slice(blob.indexOf('.') + 1), 'base64url');
      body[body.length - 20] ^= 0x01;
      return `${blob.slice(0, blob.indexOf('.') + 1)}${body.toString('base64url')}`;
    })();
    const attempts: [string, string, string][] = [
      [blob, 'user-2', KEY_A],
      [blob, 'user-1', KEY_B],
      [flipped, 'user-1', KEY_A],
      [blob.slice(0, 20), 'user-1', KEY_A],
      ['not-a-blob', 'user-1', KEY_A],
    ];
    for (const [b, user, key] of attempts) {
      let error: unknown;
      try {
        decryptTotpSecret(b, user, key);
      } catch (err) {
        error = err;
      }
      expect(error, `${user} ${key === KEY_A ? 'A' : 'B'}`).toBeInstanceOf(Error);
      expect(String((error as Error).message)).not.toContain(secret);
    }
  });

  it('verifyTotp checks the stored secret and enforces totpLastStep', () => {
    const secret = generateTotpSecret();
    const nowSec = 1_800_000_015; // mid-step
    const step = Math.floor(nowSec / 30);
    const user = { id: 'user-9', totpSecretEnc: encryptTotpSecret(secret, 'user-9', KEY_A) };
    const opts = { now: at(nowSec), keyB64: KEY_A };

    expect(verifyTotp({ ...user, totpLastStep: null }, codeAt(secret, nowSec), opts)).toBe(step);
    expect(verifyTotp({ ...user, totpLastStep: step }, codeAt(secret, nowSec), opts)).toBeNull();
    expect(verifyTotp({ ...user, totpLastStep: step }, codeAt(secret, nowSec + 30), opts)).toBe(
      step + 1,
    );
    expect(verifyTotp({ ...user, totpLastStep: null }, codeAt(secret, nowSec + 90), opts)).toBe(
      null,
    );
    // No stored secret: nothing verifies, whatever the code.
    const noSecret = { id: 'user-9', totpSecretEnc: null, totpLastStep: null };
    expect(verifyTotp(noSecret, codeAt(secret, nowSec), opts)).toBeNull();
  });
});
