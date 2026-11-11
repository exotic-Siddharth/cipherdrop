/** Text of the files users download next to the on-screen secrets (recovery key, backup codes). */

export const RECOVERY_FILE_NAME = 'cipherdrop-recovery-key.txt';

/** Contents of the downloadable .txt (the key plus plain advice). */
export function recoveryKeyFileText(recoveryKey: string, now = new Date()): string {
  return [
    'CipherDrop recovery key',
    `Created: ${now.toISOString().slice(0, 10)}`,
    '',
    recoveryKey,
    '',
    'This key is the only way back into your account if you forget your password.',
    'CipherDrop cannot see it and cannot reset it for you. Anyone who has it and your email',
    'can reset your password, so keep it somewhere private (a password manager or a printout).',
    '',
  ].join('\n');
}

export const BACKUP_CODES_FILE_NAME = 'cipherdrop-backup-codes.txt';

export function backupCodesFileText(codes: readonly string[], now = new Date()): string {
  return [
    'CipherDrop backup codes',
    `Created: ${now.toISOString().slice(0, 10)}`,
    '',
    ...codes,
    '',
    'Each code works once, in place of an authenticator code, when you log in.',
    'Keep them private. Making new codes invalidates this list.',
    '',
  ].join('\n');
}
