import { Check, FileLock, KeyRound, ShieldCheck, TriangleAlert, X } from 'lucide-react';
import type { ReactNode } from 'react';
import { PageHeader } from '../../components/layout/PageHeader';
import { ButtonLink } from '../../components/ui/Button';
import { Card, CardContent } from '../../components/ui/Card';
import { FragmentDiagram, KeyHierarchyDiagram, StreamDiagram } from './diagrams';

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

const SERVER_SEES = [
  'Encrypted file bytes, in numbered chunks',
  'How big the drop is, and how many files it has',
  'When it was made, when it expires, and how many downloads are left',
  'A hash of the drop password, if you set one (never the password)',
  'For accounts: your email, a hash of a derived login proof, and your keys in wrapped form',
  'A network prefix and browser summary for security events, such as "203.0.113.0/24, Chrome"',
];

const SERVER_NEVER = [
  'File names, file types or your note: they are encrypted too',
  'The decryption key in the link after the #',
  'Your account password or your recovery key',
  'Your account key or any drop key in a usable form',
  'The contents of any file, at any point',
];

const LIMITATIONS = [
  {
    title: 'Anyone with the full link can open the drop.',
    text: 'The key is part of the link, so share it only through a channel you trust. Add a password for a second factor the link alone cannot give.',
  },
  {
    title: 'You have to trust the code your browser runs.',
    text: 'CipherDrop serves the app that does the encrypting. A compromised server could in theory serve a modified app, as with any web app. A strict content security policy, no third-party scripts and open source code reduce that risk but do not remove it.',
  },
  {
    title: 'Lose your password and recovery key, lose your account.',
    text: 'We cannot reset what we cannot read. Drops you already shared keep working until they expire, but you could no longer manage them.',
  },
  {
    title: 'Metadata is not hidden.',
    text: 'The server knows that a drop of a given size exists, when it was created and when it was fetched, and the network prefix that did it.',
  },
  {
    title: 'A recipient can keep what they download.',
    text: 'Download limits and expiry control our copy, not the copies people have already saved.',
  },
  {
    title: 'Large files in some browsers.',
    text: 'Files over 256 MB need a browser that can stream to disk. Otherwise the page tells you before it starts.',
  },
];

function Figure({
  title,
  caption,
  children,
}: {
  title: string;
  caption: ReactNode;
  children: ReactNode;
}) {
  return (
    <figure className="flex min-w-0 flex-col gap-3">
      <div className="rounded-xl border border-border bg-surface-2/60 p-2 sm:p-5">{children}</div>
      <figcaption className="text-sm leading-relaxed text-muted-strong">
        <span className="font-semibold text-foreground">{title}. </span>
        {caption}
      </figcaption>
    </figure>
  );
}

function Section({
  id,
  number,
  title,
  children,
}: {
  id: string;
  number: number;
  title: string;
  children: ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="scroll-mt-24">
      <Card>
        <CardContent className="flex flex-col gap-5 px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <span
              aria-hidden="true"
              className="inline-flex size-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground"
            >
              {number}
            </span>
            <h2 id={id} className="text-xl font-semibold tracking-tight text-foreground">
              {title}
            </h2>
          </div>
          {children}
        </CardContent>
      </Card>
    </section>
  );
}

function Prose({ children }: { children: ReactNode }) {
  return (
    <div className="flex max-w-prose flex-col gap-3 text-base leading-relaxed text-muted">
      {children}
    </div>
  );
}

export function Component() {
  return (
    <>
      <PageHeader
        title="How it works"
        description="How CipherDrop encrypts your files in the browser, and what our server can and cannot see."
      />

      <div className="mb-8 grid gap-4 md:grid-cols-3">
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

      <div className="flex flex-col gap-6">
        <Section id="fragment" number={1} title="The key sits in the link, after the #">
          <div className="grid items-start gap-6 lg:grid-cols-2">
            <Prose>
              <p>
                When you send files, your browser makes a fresh random key for that drop. It is put
                in the link after the <code className="font-mono text-sm">#</code>, the
                &ldquo;fragment&rdquo;.
              </p>
              <p>
                By design, browsers keep the fragment to themselves: it is never part of the request
                they send. So our server gets the address of the drop, but not the key that opens
                it. The recipient&rsquo;s browser reads the key from the link and decrypts locally.
              </p>
            </Prose>
            <Figure
              title="Figure 1"
              caption="The server only ever sees the part of the link before the hash."
            >
              <FragmentDiagram />
            </Figure>
          </div>
        </Section>

        <Section id="stream" number={2} title="Files are encrypted in chunks">
          <div className="grid items-start gap-6 lg:grid-cols-2">
            <Prose>
              <p>
                Each file is cut into 4 MiB chunks, so even very large files never have to fit in
                memory. Every chunk is sealed with AES-256-GCM, which both scrambles it and adds a
                tag that proves it was not changed.
              </p>
              <p>
                The nonce for each chunk is built from its position and a flag for the last chunk.
                That ties every piece to its place: a chunk that is swapped, repeated, removed or
                cut off fails its check, and the download is blocked with a clear warning instead of
                handing you a damaged file.
              </p>
            </Prose>
            <Figure
              title="Figure 2"
              caption="Chunks are sealed one by one. The names, types and note travel in an encrypted manifest."
            >
              <StreamDiagram />
            </Figure>
          </div>
        </Section>

        <Section id="sees" number={3} title="What the server sees, and what it never sees">
          <div aria-hidden="true" className="flex flex-col gap-4 sm:hidden">
            {[
              { title: 'The server stores', items: SERVER_SEES, ok: true },
              { title: 'The server never sees', items: SERVER_NEVER, ok: false },
            ].map(({ title, items, ok }) => (
              <div key={title} className="overflow-hidden rounded-xl border border-border">
                <p className="flex items-center gap-2 bg-surface-2/70 px-4 py-3 text-xs font-semibold tracking-wide text-muted-strong uppercase">
                  {ok ? (
                    <Check className="size-4 text-success" aria-hidden="true" />
                  ) : (
                    <X className="size-4 text-danger" aria-hidden="true" />
                  )}
                  {title}
                </p>
                <ul className="flex flex-col gap-2.5 px-4 py-4 text-sm">
                  {items.map((item) => (
                    <li key={item} className="flex gap-2.5 leading-relaxed text-foreground">
                      {ok ? (
                        <Check className="mt-0.5 size-4 shrink-0 text-success" aria-hidden="true" />
                      ) : (
                        <X className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden="true" />
                      )}
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="hidden overflow-hidden rounded-xl border border-border sm:block">
            <table className="w-full border-collapse text-left text-sm">
              <caption className="sr-only">
                What the server stores compared with what it never sees
              </caption>
              <thead>
                <tr className="bg-surface-2/70">
                  <th
                    scope="col"
                    className="w-1/2 px-4 py-3 text-xs font-semibold tracking-wide text-muted-strong uppercase"
                  >
                    <span className="inline-flex items-center gap-2">
                      <Check className="size-4 text-success" aria-hidden="true" />
                      The server stores
                    </span>
                  </th>
                  <th
                    scope="col"
                    className="w-1/2 border-l border-border px-4 py-3 text-xs font-semibold tracking-wide text-muted-strong uppercase"
                  >
                    <span className="inline-flex items-center gap-2">
                      <X className="size-4 text-danger" aria-hidden="true" />
                      The server never sees
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr className="align-top">
                  <td className="px-4 py-4">
                    <ul className="flex flex-col gap-2.5">
                      {SERVER_SEES.map((item) => (
                        <li key={item} className="flex gap-2.5 leading-relaxed text-foreground">
                          <Check
                            className="mt-0.5 size-4 shrink-0 text-success"
                            aria-hidden="true"
                          />
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td className="border-l border-border px-4 py-4">
                    <ul className="flex flex-col gap-2.5">
                      {SERVER_NEVER.map((item) => (
                        <li key={item} className="flex gap-2.5 leading-relaxed text-foreground">
                          <X className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden="true" />
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </Section>

        <Section id="accounts" number={4} title="Accounts without trusting us with your password">
          <div className="grid items-start gap-6 lg:grid-cols-2">
            <Prose>
              <p>
                Your password never leaves your device. Your browser stretches it with Argon2id, a
                deliberately slow function, and splits the result in two. One half is a login proof:
                the server stores only a hash of it. The other half is a key that unlocks your
                account key.
              </p>
              <p>
                The account key is random and is stored on our server only in wrapped (encrypted)
                form, once under your password and once under your recovery key. It wraps each drop
                key, which is how your dashboard shows your file names on any device. Changing your
                password re-wraps the same account key, so nothing has to be re-encrypted.
              </p>
            </Prose>
            <Figure
              title="Figure 3"
              caption="Either your password or your recovery key unlocks the account key. Nothing here is usable without one of them."
            >
              <KeyHierarchyDiagram />
            </Figure>
          </div>
        </Section>

        <Section id="limits" number={5} title="Honest limitations">
          <ul className="grid gap-4 md:grid-cols-2">
            {LIMITATIONS.map(({ title, text }) => (
              <li
                key={title}
                className="flex gap-3 rounded-xl border border-border bg-surface-2/50 p-4"
              >
                <TriangleAlert className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden="true" />
                <div>
                  <h3 className="text-sm font-semibold text-foreground">{title}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-muted">{text}</p>
                </div>
              </li>
            ))}
          </ul>
          <p className="text-sm leading-relaxed text-muted-strong">
            The full threat model, with what is and is not protected, is written down in{' '}
            <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[13px] text-foreground">
              docs/SECURITY.md
            </code>{' '}
            in the project repository.
          </p>
        </Section>

        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-primary/25 bg-primary/5 p-5 sm:p-6">
          <div>
            <p className="text-base font-semibold text-foreground">Ready to try it?</p>
            <p className="mt-1 text-sm text-muted">No account needed. Drops up to 72 hours.</p>
          </div>
          <ButtonLink to="/" size="lg" icon={FileLock}>
            Send files
          </ButtonLink>
        </div>
      </div>
    </>
  );
}
