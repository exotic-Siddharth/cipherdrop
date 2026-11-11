const GIB = 1024 ** 3;

/** Largest quota the console accepts (10 TB): a typo guard, the API itself only caps at 2^53. */
export const MAX_QUOTA_GB = 10_240;

export type QuotaParse = { ok: true; bytes: number } | { ok: false; error: string };

/**
 * Validate a quota typed in GB ("5", "2.5", "0.25"): a plain positive decimal with at most two decimals, at
 * most MAX_QUOTA_GB. Returns whole bytes (1 GB = 1024^3, like formatBytes) or the message to show.
 */
export function parseQuotaGb(input: string): QuotaParse {
  const text = input.trim();
  if (text === '') return { ok: false, error: 'Enter a quota in GB.' };
  if (!/^\d+(\.\d{1,2})?$/.test(text)) {
    return { ok: false, error: 'Use a plain number such as 5 or 2.5 (at most two decimals).' };
  }
  const gb = Number(text);
  if (gb <= 0) return { ok: false, error: 'The quota must be greater than 0 GB.' };
  if (gb > MAX_QUOTA_GB) {
    return { ok: false, error: `The quota cannot exceed ${MAX_QUOTA_GB.toLocaleString('en')} GB.` };
  }
  return { ok: true, bytes: Math.round(gb * GIB) };
}

/** Bytes as a GB string for the edit field: 5368709120 -> "5", 2684354560 -> "2.5". */
export function quotaToGbText(bytes: number): string {
  const gb = Math.round((bytes / GIB) * 100) / 100;
  return String(gb);
}
