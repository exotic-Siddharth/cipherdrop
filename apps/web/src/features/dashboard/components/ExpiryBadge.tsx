import type { DropStatus } from '@cipherdrop/shared';
import { Timer } from 'lucide-react';
import { Badge, type BadgeTone } from '../../../components/ui/Badge';
import { formatDate, formatDuration } from '../../../lib/format';
import { useNow } from '../../../lib/hooks';

const HOUR = 3_600_000;

export interface ExpiryBadgeProps {
  expiresAt: string;
  status: DropStatus;
  className?: string;
}

/** "Expires in 2 d 3 h" (amber under a day, red under an hour) or "Expired 3 h ago". Full date as a tooltip. */
export function ExpiryBadge({ expiresAt, status, className }: ExpiryBadgeProps) {
  const now = useNow(30_000);
  const remaining = new Date(expiresAt).getTime() - now;
  const live = status === 'READY' || status === 'UPLOADING';

  // Used-up and disabled drops have no meaningful countdown: the status badge says it all.
  if (!live && remaining > 0) return null;

  let label: string;
  let tone: BadgeTone = 'neutral';
  if (remaining <= 0) {
    label = `Expired ${formatDuration(-remaining, { units: 1 })} ago`;
  } else {
    label = `Expires in ${formatDuration(remaining, { units: 2 })}`;
    tone = remaining < HOUR ? 'danger' : remaining < 24 * HOUR ? 'warning' : 'neutral';
  }
  return (
    <Badge tone={tone} icon={Timer} className={className} title={formatDate(expiresAt)}>
      {label}
    </Badge>
  );
}
