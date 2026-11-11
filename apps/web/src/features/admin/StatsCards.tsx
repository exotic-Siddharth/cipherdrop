import type { AdminStats } from '@cipherdrop/shared';
import { Database, Files, Flag, Package, Users, type LucideIcon } from 'lucide-react';
import { Card } from '../../components/ui/Card';
import { cn } from '../../lib/cn';
import { formatBytes } from '../../lib/format';
import { formatCount } from './formatCount';

interface Tile {
  label: string;
  value: string;
  icon: LucideIcon;
  /** Short context line under the value. */
  note?: string;
  attention?: boolean;
}

/** Headline numbers (stat tiles: label, value, optional note). */
export function StatsCards({ stats }: { stats: AdminStats }) {
  const tiles: Tile[] = [
    { label: 'Users', value: formatCount(stats.users), icon: Users },
    { label: 'Active drops', value: formatCount(stats.activeDrops), icon: Package },
    { label: 'Total drops', value: formatCount(stats.totalDrops), icon: Files },
    { label: 'Storage used', value: formatBytes(stats.storageBytes), icon: Database },
    {
      label: 'Open reports',
      value: formatCount(stats.openReports),
      icon: Flag,
      note: stats.openReports > 0 ? 'Needs review' : 'Queue is clear',
      attention: stats.openReports > 0,
    },
  ];
  return (
    <ul className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-5" aria-label="Statistics">
      {tiles.map((t) => (
        <li
          key={t.label}
          className={t.label === 'Open reports' ? 'col-span-2 lg:col-span-1' : undefined}
        >
          <Card
            className={cn('h-full p-4 sm:p-5', t.attention && 'border-warning/40 bg-warning/5')}
          >
            <p className="flex items-center gap-2 text-sm text-muted-strong">
              <t.icon className="size-4 shrink-0" aria-hidden="true" />
              {t.label}
            </p>
            <p className="mt-2 text-3xl font-semibold tracking-tight text-foreground">{t.value}</p>
            {t.note ? (
              <p
                className={cn(
                  'mt-1 text-xs',
                  t.attention ? 'font-medium text-warning-ink' : 'text-muted-strong',
                )}
              >
                {t.note}
              </p>
            ) : null}
          </Card>
        </li>
      ))}
    </ul>
  );
}
