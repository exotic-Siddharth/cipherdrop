/**
 * Effective storage quota (server-1). A new account is on probation until `quotaProbationEndsAt` (set at
 * registration to NEW_ACCOUNT_PROBATION_DAYS ahead): its quota is then at most NEW_ACCOUNT_QUOTA_BYTES. An
 * admin's quota edit clears the date, so the admin's value applies at once. Read at check time, so changing
 * NEW_ACCOUNT_QUOTA_BYTES applies to accounts already on probation; the end date stays as registered.
 */
import type { User } from '@prisma/client';
import type { Env } from '../config/env';

type QuotaFields = Pick<User, 'storageQuotaBytes' | 'quotaProbationEndsAt'>;

/** The end of the probation, or null when none applies at `now`. */
export function probationEndsAt(user: Pick<User, 'quotaProbationEndsAt'>, now: Date): Date | null {
  const end = user.quotaProbationEndsAt;
  return end !== null && end.getTime() > now.getTime() ? end : null;
}

/** The quota that applies at `now`: the stored quota, capped by the probation quota while it lasts. */
export function effectiveQuotaBytes(
  user: QuotaFields,
  env: Pick<Env, 'NEW_ACCOUNT_QUOTA_BYTES'>,
  now: Date,
): bigint {
  if (!probationEndsAt(user, now)) return user.storageQuotaBytes;
  const cap = BigInt(env.NEW_ACCOUNT_QUOTA_BYTES);
  return user.storageQuotaBytes < cap ? user.storageQuotaBytes : cap;
}
