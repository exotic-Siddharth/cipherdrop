import { FileLock, KeyRound, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card, CardContent } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

const STEPS = [
  {
    icon: KeyRound,
    title: 'A key only you hold',
    text: 'Your browser creates a random key for every drop and puts it after the # of the link. Browsers never send that part to a server.',
  },
  {
    icon: FileLock,
    title: 'Encrypted before upload',
    text: 'Files are split into 4 MiB chunks and sealed with AES-256-GCM, so any change, reorder or cut is detected.',
  },
  {
    icon: ShieldCheck,
    title: 'The server sees ciphertext',
    text: 'We store encrypted bytes, sizes and timestamps. Never names, notes, keys or passwords.',
  },
];

/** Placeholder (S5). Lane W1 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <>
      <PageHeader
        title="How it works"
        description="How CipherDrop encrypts your files in the browser, and what our server can and cannot see."
      />
      <div className="mb-6 grid gap-4 md:grid-cols-3">
        {STEPS.map(({ icon: Icon, title, text }) => (
          <Card key={title}>
            <CardContent className="flex flex-col gap-3">
              <span className="inline-flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary-ink">
                <Icon className="size-5" aria-hidden="true" />
              </span>
              <h2 className="text-base font-semibold text-foreground">{title}</h2>
              <p className="text-sm leading-relaxed text-muted">{text}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <EmptyState
          icon={ShieldCheck}
          size="sm"
          title="The full explainer lands here"
          description="Diagrams of the key hierarchy and the chunked encryption, plus honest limitations, are built in lane W1."
        />
      </Card>
    </>
  );
}
