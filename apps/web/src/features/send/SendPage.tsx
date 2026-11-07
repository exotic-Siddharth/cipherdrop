import { Flame, KeyRound, Lock, Timer } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

const POINTS = [
  { icon: Lock, text: 'AES-256-GCM in your browser' },
  { icon: KeyRound, text: 'The key stays in the link' },
  { icon: Timer, text: 'Links expire on schedule' },
  { icon: Flame, text: 'Burn after reading' },
];

/** Placeholder (S5). Lane W2 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <>
      <PageHeader
        eyebrow="End-to-end encrypted"
        title="Send files"
        description="Share files only the recipient can read. Not even us."
      />
      <ul className="mb-6 flex flex-wrap gap-2">
        {POINTS.map(({ icon: Icon, text }) => (
          <li
            key={text}
            className="inline-flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1.5 text-sm text-foreground shadow-card"
          >
            <Icon className="size-4 text-primary" aria-hidden="true" />
            {text}
          </li>
        ))}
      </ul>
      <Card>
        <EmptyState
          icon={Lock}
          title="The encrypted send flow lands here"
          description="Drop zone, expiry and download options, password protection and the upload progress view are built in lane W2."
        />
      </Card>
    </>
  );
}
