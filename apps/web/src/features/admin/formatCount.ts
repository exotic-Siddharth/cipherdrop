const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
/** 1,284 below 10 000, then 12.9K / 4.2M. */
export function formatCount(n: number): string {
  return n < 10_000 ? n.toLocaleString('en') : compact.format(n);
}
