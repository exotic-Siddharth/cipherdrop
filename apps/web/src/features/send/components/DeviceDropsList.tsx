import { History, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Button, Card, CardContent, CardHeader, ConfirmDialog } from '../../../components/ui';
import { formatDate, formatRelative } from '../../../lib/format';
import { useNow } from '../../../lib/hooks';
import { useDeviceDrops, type DeviceDrop } from '../../../stores/deviceDrops';
import { deleteDrop } from '../sendFlow';

/** "Sent from this device": anonymous drops remembered by id + owner token only (no names, no keys). */
export function DeviceDropsList() {
  const drops = useDeviceDrops((s) => s.drops);
  const now = useNow(60_000);
  const [pending, setPending] = useState<DeviceDrop | null>(null);

  useEffect(() => {
    useDeviceDrops.getState().sync(now);
  }, [now]);

  useEffect(() => {
    const onStorage = () => useDeviceDrops.getState().sync();
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  if (drops.length === 0) return null;

  return (
    <Card as="section" aria-labelledby="device-drops-title">
      <CardHeader
        icon={History}
        title={<span id="device-drops-title">Sent from this device</span>}
        description="Anonymous drops this browser created. Only the drop id and its delete token are kept here: no file names, no keys."
        titleAs="h2"
      />
      <CardContent className="pt-0">
        <ul className="divide-y divide-border rounded-lg border border-border">
          {drops.map((d) => (
            <li
              key={d.dropId}
              className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2.5 sm:px-4"
            >
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-sm text-foreground">{d.dropId}</span>
                <span className="block text-xs text-muted">
                  Sent {formatRelative(d.createdAt, now)} ·{' '}
                  <span title={formatDate(d.expiresAt)}>
                    expires {formatRelative(d.expiresAt, now)}
                  </span>
                </span>
              </span>
              <Button
                variant="ghost"
                size="sm"
                icon={Trash2}
                className="text-danger-ink"
                aria-label={`Delete drop ${d.dropId}`}
                onClick={() => setPending(d)}
              >
                Delete
              </Button>
            </li>
          ))}
        </ul>
      </CardContent>
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => !open && setPending(null)}
        title="Delete this drop?"
        description="The encrypted files are removed from the server right away and the link stops working."
        confirmLabel="Delete drop"
        tone="danger"
        onConfirm={async () => {
          if (!pending) return;
          await deleteDrop(pending.dropId, pending.ownerToken);
          useDeviceDrops.getState().remove(pending.dropId);
          toast.success('Drop deleted');
          setPending(null);
        }}
      />
    </Card>
  );
}
