import { ShieldCheck } from 'lucide-react';
import { Link } from 'react-router';
import { Logo } from './Logo';

const linkClass =
  'rounded text-muted-strong underline-offset-4 transition-colors hover:text-foreground hover:underline';

/** Site footer: what CipherDrop does with your files, in one sentence, plus the key links. */
export function Footer() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-10 sm:flex-row sm:items-start sm:justify-between sm:px-6">
        <div className="flex max-w-md flex-col gap-3">
          <Logo size="sm" />
          <p className="text-sm leading-relaxed text-muted-strong">
            Files are encrypted in your browser with AES-256-GCM before they are uploaded. The key
            travels in the link and never reaches our servers.
          </p>
        </div>
        <nav aria-label="Footer">
          <ul className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
            <li>
              <Link to="/" className={linkClass}>
                Send files
              </Link>
            </li>
            <li>
              <Link to="/how-it-works" className={linkClass}>
                How it works
              </Link>
            </li>
            <li>
              <a href="/api/docs" className={linkClass}>
                API docs
              </a>
            </li>
          </ul>
        </nav>
      </div>
      <div className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-4 text-xs text-muted-strong sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <p>© {new Date().getFullYear()} CipherDrop · MIT licensed</p>
          <p className="flex items-center gap-1.5">
            <ShieldCheck className="size-3.5 text-primary" aria-hidden="true" />
            No trackers, no third-party scripts, no plaintext on the server.
          </p>
        </div>
      </div>
    </footer>
  );
}
