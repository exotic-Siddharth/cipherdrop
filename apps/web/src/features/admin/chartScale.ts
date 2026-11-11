/** Axis helpers for the uploads chart. Pure, so they are unit-tested without a DOM. */

/** Smallest 1-2-5 step (times a power of ten) that covers `max` in at most `count` + 1 intervals. */
function niceStep(max: number, count: number): number {
  for (let exp = Math.floor(Math.log10(max / count)) - 1; ; exp += 1) {
    for (const m of [1, 2, 5]) {
      const step = m * 10 ** exp;
      if (Math.ceil(max / step) <= count + 1) return step;
    }
  }
}

/**
 * Round tick values from 0 up to a "nice" ceiling that is >= max, about `count` intervals.
 * Counts use 1-2-5 decimal steps (whole numbers only); byte sizes use 1-2-5 steps inside the largest binary
 * unit that fits (so ticks read 0 / 50 MB / 100 MB, never 0 / 47.7 MB).
 */
export function niceTicks(max: number, kind: 'count' | 'bytes', count = 4): number[] {
  if (!Number.isFinite(max) || max <= 0) return kind === 'bytes' ? [0, 1024] : [0, 1];
  let step: number;
  if (kind === 'bytes') {
    const unit = 1024 ** Math.max(0, Math.floor(Math.log(max) / Math.log(1024)));
    step = niceStep(max / unit, count) * unit;
  } else {
    step = Math.max(1, niceStep(max, count));
  }
  const top = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(v);
  return ticks;
}
