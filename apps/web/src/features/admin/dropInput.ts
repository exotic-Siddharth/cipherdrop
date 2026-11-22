import { DropIdSchema } from '@cipherdrop/shared';

/**
 * The drop id from what the admin pasted: a bare id or a whole share link. Everything from `#` on (the key) is
 * cut off first, so it is never sent anywhere.
 */
export function dropIdFromInput(value: string): string | null {
  const path = value.trim().split('#')[0] ?? '';
  const last = path.split('?')[0]?.split('/').filter(Boolean).pop() ?? '';
  return DropIdSchema.safeParse(last).success ? last : null;
}
