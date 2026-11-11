import type { AuditAction } from '@cipherdrop/shared';
import {
  Ban,
  CircleCheck,
  Download,
  Eye,
  FileLock2,
  Flag,
  Flame,
  KeyRound,
  LifeBuoy,
  Lock,
  LogIn,
  LogOut,
  MonitorX,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Timer,
  Trash2,
  TriangleAlert,
  UserPlus,
  UserX,
  type LucideIcon,
} from 'lucide-react';

export interface AuditPresentation {
  icon: LucideIcon;
  /** Tone class for the icon chip. */
  tone: 'neutral' | 'primary' | 'success' | 'warning' | 'danger';
}

/** One icon and tone per audit action (labels come from AUDIT_ACTION_LABELS in @cipherdrop/shared). */
export const AUDIT_PRESENTATION: Readonly<Record<AuditAction, AuditPresentation>> = Object.freeze({
  REGISTER: { icon: UserPlus, tone: 'primary' },
  LOGIN_SUCCESS: { icon: LogIn, tone: 'neutral' },
  LOGIN_FAILURE: { icon: ShieldAlert, tone: 'warning' },
  LOGIN_LOCKED: { icon: Lock, tone: 'danger' },
  MFA_CHALLENGE_FAILED: { icon: ShieldAlert, tone: 'warning' },
  MFA_ENABLED: { icon: ShieldCheck, tone: 'success' },
  MFA_DISABLED: { icon: ShieldOff, tone: 'warning' },
  BACKUP_CODE_USED: { icon: KeyRound, tone: 'warning' },
  BACKUP_CODES_REGENERATED: { icon: KeyRound, tone: 'neutral' },
  PASSWORD_CHANGED: { icon: KeyRound, tone: 'primary' },
  RECOVERY_USED: { icon: LifeBuoy, tone: 'warning' },
  RECOVERY_KEY_ROTATED: { icon: LifeBuoy, tone: 'primary' },
  SESSION_REVOKED: { icon: MonitorX, tone: 'neutral' },
  SESSION_REUSE_DETECTED: { icon: TriangleAlert, tone: 'danger' },
  LOGOUT: { icon: LogOut, tone: 'neutral' },
  ACCOUNT_DELETED: { icon: UserX, tone: 'danger' },
  DROP_CREATED: { icon: FileLock2, tone: 'primary' },
  DROP_COMPLETED: { icon: CircleCheck, tone: 'success' },
  DROP_OPENED: { icon: Download, tone: 'primary' },
  DROP_UNLOCK_FAILED: { icon: ShieldAlert, tone: 'warning' },
  DROP_DELETED: { icon: Trash2, tone: 'neutral' },
  DROP_EXPIRED: { icon: Timer, tone: 'neutral' },
  DROP_EXHAUSTED: { icon: Flame, tone: 'neutral' },
  DROP_REPORTED: { icon: Flag, tone: 'warning' },
  DROP_DISABLED: { icon: Ban, tone: 'danger' },
  ADMIN_REVIEW_GRANT: { icon: Eye, tone: 'neutral' },
});

export const TONE_CLASSES: Record<AuditPresentation['tone'], string> = {
  neutral: 'bg-surface-2 text-muted',
  primary: 'bg-primary/10 text-primary-ink',
  success: 'bg-success/10 text-success-ink',
  warning: 'bg-warning/10 text-warning-ink',
  danger: 'bg-danger/10 text-danger-ink',
};
