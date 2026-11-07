import QRCode from 'qrcode';
import { useMemo } from 'react';
import { cn } from '../lib/cn';

export interface QrCodeProps {
  /** Text to encode (share link, otpauth:// URL). It never leaves the page. */
  value: string;
  /** Rendered size in CSS pixels (default 192). */
  size?: number;
  /** Accessible name, e.g. "QR code for the share link". */
  label: string;
  errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
  className?: string;
}

/** Quiet zone in modules (the QR spec asks for 4). */
const QUIET_ZONE = 4;

function buildPath(value: string, level: QrCodeProps['errorCorrectionLevel']) {
  try {
    const { modules } = QRCode.create(value, { errorCorrectionLevel: level });
    const n = modules.size;
    let d = '';
    for (let row = 0; row < n; row += 1) {
      let col = 0;
      while (col < n) {
        if (!modules.data[row * n + col]) {
          col += 1;
          continue;
        }
        const start = col;
        while (col < n && modules.data[row * n + col]) col += 1;
        const run = col - start;
        d += `M${start + QUIET_ZONE} ${row + QUIET_ZONE}h${run}v1h-${run}z`;
      }
    }
    return { d, dimension: n + QUIET_ZONE * 2 };
  } catch {
    return null; // value too long for a QR code
  }
}

/**
 * QR code rendered locally with `qrcode` into an inline SVG (spec 11.2, R8): no image service, no canvas, no
 * innerHTML. Always dark-on-white, also in dark mode, so every scanner reads it.
 */
export function QrCode({
  value,
  size = 192,
  label,
  errorCorrectionLevel = 'M',
  className,
}: QrCodeProps) {
  const qr = useMemo(() => buildPath(value, errorCorrectionLevel), [value, errorCorrectionLevel]);
  if (!qr) {
    return (
      <div
        role="img"
        aria-label={`${label} (unavailable)`}
        style={{ width: size, height: size }}
        className={cn(
          'grid place-items-center rounded-lg border border-dashed border-border-strong p-4 text-center text-xs text-muted-strong',
          className,
        )}
      >
        Too long for a QR code
      </div>
    );
  }
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${qr.dimension} ${qr.dimension}`}
      shapeRendering="crispEdges"
      className={cn('rounded-lg', className)}
    >
      <rect width={qr.dimension} height={qr.dimension} fill="#ffffff" />
      <path d={qr.d} fill="#0f172a" />
    </svg>
  );
}
