export type MeterSeverity = 'ok' | 'warning' | 'danger';

/** Fill severity: accent below 80 %, warning from 80 %, danger from 95 %. */
export function meterSeverity(used: number, quota: number): MeterSeverity {
  if (quota <= 0) return used > 0 ? 'danger' : 'ok';
  const ratio = used / quota;
  if (ratio >= 0.95) return 'danger';
  if (ratio >= 0.8) return 'warning';
  return 'ok';
}
