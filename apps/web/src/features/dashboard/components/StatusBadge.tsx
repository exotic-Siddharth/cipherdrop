import type { DropStatus } from '@cipherdrop/shared';
import { Ban, CircleCheck, Flame, Timer, Trash2, Upload, type LucideIcon } from 'lucide-react';
import { Badge, type BadgeTone } from '../../../components/ui/Badge';

const STATUS: Record<DropStatus, { label: string; tone: BadgeTone; icon: LucideIcon }> = {
  UPLOADING: { label: 'Uploading', tone: 'warning', icon: Upload },
  READY: { label: 'Active', tone: 'success', icon: CircleCheck },
  EXHAUSTED: { label: 'Downloads used', tone: 'neutral', icon: Flame },
  EXPIRED: { label: 'Expired', tone: 'neutral', icon: Timer },
  DISABLED: { label: 'Disabled', tone: 'danger', icon: Ban },
  DELETED: { label: 'Deleted', tone: 'neutral', icon: Trash2 },
};

export interface StatusBadgeProps {
  status: DropStatus;
  className?: string;
}

/** Drop status as an icon plus a word, so the state is never carried by colour alone. */
export function StatusBadge({ status, className }: StatusBadgeProps) {
  const { label, tone, icon } = STATUS[status];
  return (
    <Badge tone={tone} icon={icon} className={className}>
      {label}
    </Badge>
  );
}
