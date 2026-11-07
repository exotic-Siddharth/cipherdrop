/**
 * Test data factories (S3). Users are inserted with PRE-COMPUTED zero-knowledge fields, so tests do not run
 * client-side Argon2id for every user.
 *
 * TEST_ACCOUNT uses FIXED BYTES: its wrapped keys are not derivable from `password` (packages/crypto was a stub
 * when this was written). Server-side flows (login with authKey, vault, recovery start with recoveryAuthKey) work
 * as-is. Tests that need client-consistent material should derive it with @cipherdrop/crypto in the test file.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { Prisma, PrismaClient, User } from '@prisma/client';
import { hashAuthKey } from '../src/lib/argon2';
import { signAccessToken } from '../src/lib/jwt';

const bytes = (start: number, length: number) =>
  Buffer.from(Array.from({ length }, (_, i) => (start + i) & 0xff));

const authKeyBytes = bytes(0x20, 32);
const recoveryAuthKeyBytes = bytes(0xc0, 32);

export const TEST_ACCOUNT = Object.freeze({
  password: 'correct horse battery staple (test account)',
  /** Argon2id params at KDF_MIN so client-side derivations in tests stay fast. salt = bytes 0x00..0x0f. */
  kdf: Object.freeze({
    salt: 'AAECAwQFBgcICQoLDA0ODw',
    memoryKiB: 19456,
    iterations: 2,
    parallelism: 1,
  }),
  /** b64url(bytes 0x20..0x3f): what a client would send as `authKey`. */
  authKey: authKeyBytes.toString('base64url'),
  authKeyBytes: Uint8Array.from(authKeyBytes),
  /** 80-char wrapped keys (fixed bytes). */
  wrappedAccountKey: bytes(0x40, 60).toString('base64url'),
  wrappedAccountKeyRecovery: bytes(0x80, 60).toString('base64url'),
  /** b64url(bytes 0xc0..0xdf): what a client would send as `recoveryAuthKey`. */
  recoveryAuthKey: recoveryAuthKeyBytes.toString('base64url'),
  /** b64url(SHA-256(recoveryAuthKey bytes)), as hashForServer would compute it. */
  recoveryAuthHash: createHash('sha256').update(recoveryAuthKeyBytes).digest('base64url'),
});

let authKeyHashPromise: Promise<string> | undefined;
/** Server-side Argon2id PHC hash of TEST_ACCOUNT.authKey, computed once per test file. */
export function testAuthKeyHash(): Promise<string> {
  authKeyHashPromise ??= hashAuthKey(TEST_ACCOUNT.authKeyBytes);
  return authKeyHashPromise;
}

let counter = 0;
export function uniqueEmail(label = 'user'): string {
  counter += 1;
  return `${label}${counter}-${randomUUID().slice(0, 8)}@test.local`;
}

/** Insert a user whose login authKey is TEST_ACCOUNT.authKey (unless authKeyHash is overridden). */
export async function createUserRecord(
  prisma: PrismaClient,
  overrides: Partial<Prisma.UserCreateInput> = {},
): Promise<User> {
  const data: Prisma.UserCreateInput = {
    email: uniqueEmail(),
    role: 'USER',
    authKeyHash: await testAuthKeyHash(),
    kdfSalt: TEST_ACCOUNT.kdf.salt,
    kdfMemoryKiB: TEST_ACCOUNT.kdf.memoryKiB,
    kdfIterations: TEST_ACCOUNT.kdf.iterations,
    kdfParallelism: TEST_ACCOUNT.kdf.parallelism,
    wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
    wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
    recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
    storageQuotaBytes: BigInt(5 * 1024 * 1024 * 1024),
    ...overrides,
  };
  return prisma.user.create({ data });
}

export function createAdminRecord(
  prisma: PrismaClient,
  overrides: Partial<Prisma.UserCreateInput> = {},
): Promise<User> {
  return createUserRecord(prisma, { email: uniqueEmail('admin'), role: 'ADMIN', ...overrides });
}

/**
 * `Authorization` header value with a valid access token for `user`. The auth middleware only verifies the JWT
 * and the sid denylist, so no Session row is needed unless the code under test looks the session up.
 */
export function authHeader(user: Pick<User, 'id' | 'role'>, sid = `sid-${randomUUID()}`): string {
  return `Bearer ${signAccessToken({ id: user.id, role: user.role }, sid)}`;
}
