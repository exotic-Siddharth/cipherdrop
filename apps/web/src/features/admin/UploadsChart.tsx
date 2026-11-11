import type { AdminStats } from '@cipherdrop/shared';
import { ChartColumn, Table2 } from 'lucide-react';
import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Button } from '../../components/ui/Button';
import { Card, CardContent, CardHeader } from '../../components/ui/Card';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../../components/ui/Table';
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/Tabs';
import { cn } from '../../lib/cn';
import { formatBytes, pluralize } from '../../lib/format';
import { niceTicks } from './chartScale';

type Day = AdminStats['uploadsLast14d'][number];
type Measure = 'drops' | 'bytes';

const PLOT_HEIGHT = 176; // px, the area the bars grow in

/** "YYYY-MM-DD" (UTC) parts without a timezone shift. */
function dayParts(date: string): { day: number; month: string; long: string } {
  const d = new Date(`${date}T00:00:00Z`);
  const fmt = (o: Intl.DateTimeFormatOptions) =>
    new Intl.DateTimeFormat('en-GB', { ...o, timeZone: 'UTC' }).format(d);
  return {
    day: d.getUTCDate(),
    month: fmt({ month: 'short' }),
    long: fmt({ weekday: 'short', day: 'numeric', month: 'short' }),
  };
}

const describe = (d: Day) => `${pluralize(d.drops, 'drop')}, ${formatBytes(d.bytes)}`;

export interface UploadsChartProps {
  days: AdminStats['uploadsLast14d'];
}

/**
 * Uploads per day for the last 14 days (UTC). One series, one axis: a switch picks the measure (drops or
 * bytes) instead of a dual-axis chart. Columns are focusable (arrow keys), hover/focus shows a tooltip, and a
 * table view carries every value.
 */
export function UploadsChart({ days }: UploadsChartProps) {
  const [measure, setMeasure] = useState<Measure>('drops');
  const [asTable, setAsTable] = useState(false);
  const [active, setActive] = useState(days.length - 1);
  const cols = useRef<Array<HTMLButtonElement | null>>([]);
  const tableId = useId();

  const values = days.map((d) => d[measure]);
  const max = Math.max(0, ...values);
  const ticks = useMemo(
    () => niceTicks(max, measure === 'bytes' ? 'bytes' : 'count'),
    [max, measure],
  );
  const top = ticks[ticks.length - 1] ?? 1;
  const format = (v: number) => (measure === 'bytes' ? formatBytes(v) : String(v));
  const peak = max > 0 ? values.indexOf(max) : -1;
  const totalDrops = days.reduce((s, d) => s + d.drops, 0);
  const totalBytes = days.reduce((s, d) => s + d.bytes, 0);
  const first = days[0];
  const last = days[days.length - 1];

  const onKey = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    const next =
      e.key === 'ArrowRight'
        ? Math.min(days.length - 1, i + 1)
        : e.key === 'ArrowLeft'
          ? Math.max(0, i - 1)
          : e.key === 'Home'
            ? 0
            : e.key === 'End'
              ? days.length - 1
              : -1;
    if (next < 0) return;
    e.preventDefault();
    setActive(next);
    cols.current[next]?.focus();
  };

  return (
    <Card as="section" aria-labelledby="uploads-chart-title">
      <CardHeader
        icon={ChartColumn}
        title={<span id="uploads-chart-title">Uploads, last 14 days</span>}
        description={
          first && last
            ? `${dayParts(first.date).long} to ${dayParts(last.date).long}, days in UTC`
            : undefined
        }
        actions={
          <Button
            variant="outline"
            size="sm"
            icon={asTable ? ChartColumn : Table2}
            aria-pressed={asTable}
            aria-controls={tableId}
            onClick={() => setAsTable((v) => !v)}
          >
            {asTable ? 'Chart view' : 'Table view'}
          </Button>
        }
      />
      <CardContent className="pt-4 sm:pt-4">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
          <p className="min-w-0">
            <span className="text-3xl font-semibold tracking-tight text-foreground">
              {measure === 'drops' ? totalDrops.toLocaleString('en') : formatBytes(totalBytes)}
            </span>
            <span className="ml-2 text-sm text-muted-strong">
              {measure === 'drops' ? 'drops' : 'uploaded'} in 14 days
            </span>
          </p>
          <Tabs
            value={measure}
            onValueChange={(v) => setMeasure(v === 'bytes' ? 'bytes' : 'drops')}
            variant="pills"
          >
            <TabsList aria-label="Chart measure">
              <TabsTrigger value="drops">Drops</TabsTrigger>
              <TabsTrigger value="bytes">Bytes</TabsTrigger>
            </TabsList>
          </Tabs>
        </div>

        <div id={tableId}>
          {asTable ? (
            <Table containerClassName="rounded-lg border border-border">
              <TableCaption className="sr-only">Uploads per day, last 14 days (UTC)</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Day</TableHead>
                  <TableHead className="text-right">Drops</TableHead>
                  <TableHead className="text-right">Uploaded</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {days.map((d) => (
                  <TableRow key={d.date}>
                    <TableCell>{dayParts(d.date).long}</TableCell>
                    <TableCell className="text-right tabular-nums">{d.drops}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatBytes(d.bytes)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div role="group" aria-label={`Uploads per day, ${measure}`}>
              <div className="min-w-0 flex-1">
                <div className="relative mt-4" style={{ height: PLOT_HEIGHT }}>
                  {ticks.map((t) => (
                    <div
                      key={t}
                      aria-hidden="true"
                      className="absolute left-16 right-0"
                      style={{ bottom: `${(t / top) * 100}%` }}
                    >
                      <span className="absolute -left-16 w-14 -translate-y-1/2 whitespace-nowrap pr-2 text-right text-xs tabular-nums text-muted-strong">
                        {format(t)}
                      </span>
                      <div
                        className={cn(
                          'border-t',
                          t === 0 ? 'border-border-strong/60' : 'border-border',
                        )}
                      />
                    </div>
                  ))}
                  {max === 0 ? (
                    <p className="absolute inset-0 flex items-center justify-center text-sm text-muted-strong">
                      No uploads in this period
                    </p>
                  ) : null}
                  <div
                    className="absolute inset-y-0 left-16 right-0 grid"
                    style={{ gridTemplateColumns: `repeat(${days.length}, minmax(0, 1fr))` }}
                  >
                    {days.map((d, i) => {
                      const v = d[measure];
                      const pct = (v / top) * 100;
                      const parts = dayParts(d.date);
                      const edge =
                        i < 3
                          ? 'left-0'
                          : i > days.length - 4
                            ? 'right-0'
                            : 'left-1/2 -translate-x-1/2';
                      return (
                        <button
                          key={d.date}
                          ref={(el) => {
                            cols.current[i] = el;
                          }}
                          type="button"
                          tabIndex={i === active ? 0 : -1}
                          aria-label={`${parts.long}: ${describe(d)}`}
                          onFocus={() => setActive(i)}
                          onKeyDown={(e) => onKey(e, i)}
                          className="group relative flex h-full items-end justify-center rounded-md focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-primary hover:bg-surface-2/60"
                        >
                          {v > 0 ? (
                            <span
                              className="block w-[calc(100%-4px)] max-w-6 rounded-t-[4px] bg-primary"
                              style={{ height: `${pct}%`, minHeight: 3 }}
                            />
                          ) : null}
                          {i === peak ? (
                            <span
                              aria-hidden="true"
                              className="pointer-events-none absolute left-1/2 -translate-x-1/2 whitespace-nowrap text-xs font-medium tabular-nums text-foreground group-hover:invisible group-focus-visible:invisible"
                              style={{ bottom: `calc(${pct}% + 4px)` }}
                            >
                              {format(v)}
                            </span>
                          ) : null}
                          <span
                            aria-hidden="true"
                            className={cn(
                              'pointer-events-none absolute z-10 hidden w-max max-w-48 rounded-lg border border-border bg-surface px-3 py-2 text-left text-xs shadow-popover group-hover:block group-focus-visible:block',
                              edge,
                            )}
                            style={{ bottom: `calc(${Math.min(pct, 78)}% + 12px)` }}
                          >
                            <span className="block font-medium text-foreground">{parts.long}</span>
                            <span className="mt-0.5 block tabular-nums text-muted-strong">
                              {pluralize(d.drops, 'drop')}
                            </span>
                            <span className="block tabular-nums text-muted-strong">
                              {formatBytes(d.bytes)}
                            </span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
                {/* x axis: day of month, with the month where it changes */}
                <div
                  className="mt-2 ml-16 grid"
                  style={{ gridTemplateColumns: `repeat(${days.length}, minmax(0, 1fr))` }}
                  aria-hidden="true"
                >
                  {days.map((d, i) => {
                    const parts = dayParts(d.date);
                    return (
                      <span
                        key={d.date}
                        className="flex flex-col items-center text-[11px] leading-4 tabular-nums text-muted-strong"
                      >
                        {parts.day}
                        <span className="h-4">{i === 0 || parts.day === 1 ? parts.month : ''}</span>
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
