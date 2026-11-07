import { CircleAlert, FileQuestion, RefreshCw, RotateCw, Send } from 'lucide-react';
import { Component, type ReactNode } from 'react';
import { isRouteErrorResponse, useRouteError } from 'react-router';
import { AppShell } from './layout/AppShell';
import { Button, ButtonLink } from './ui/Button';
import { EmptyState } from './ui/EmptyState';

const CHUNK_ERROR =
  /dynamically imported module|Importing a module script failed|error loading dynamically imported module/i;

/**
 * If the shell itself is what crashed, render the message without it instead of failing twice. There is no
 * error reporting service by design (no third-party scripts).
 */
class ShellFallback extends Component<
  { children: ReactNode; fallback: ReactNode },
  { failed: boolean }
> {
  override state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  override render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

/** Root route ErrorBoundary: 404 responses, stale chunks after a deploy, and unexpected render errors. */
export function RouteErrorBoundary() {
  const error = useRouteError();
  if (import.meta.env.DEV) console.error(error);

  const notFound = isRouteErrorResponse(error) && error.status === 404;
  const staleChunk = error instanceof Error && CHUNK_ERROR.test(error.message);

  const content = notFound ? (
    <EmptyState
      icon={FileQuestion}
      titleAs="h1"
      title="Page not found"
      description="This address does not exist in CipherDrop."
      action={
        <ButtonLink to="/" icon={Send}>
          Send files
        </ButtonLink>
      }
    />
  ) : (
    <EmptyState
      icon={staleChunk ? RefreshCw : CircleAlert}
      tone={staleChunk ? 'default' : 'danger'}
      titleAs="h1"
      title={staleChunk ? 'CipherDrop was updated' : 'Something went wrong'}
      description={
        staleChunk
          ? 'A newer version is available. Reload the page to continue.'
          : 'The page failed to load. Reloading usually fixes it. Nothing you encrypted was sent anywhere.'
      }
      action={
        <>
          <Button icon={RotateCw} onClick={() => window.location.reload()}>
            Reload
          </Button>
          <ButtonLink to="/" variant="outline">
            Go to Send
          </ButtonLink>
        </>
      }
    />
  );

  return (
    <ShellFallback fallback={<main className="mx-auto max-w-xl px-4 py-16">{content}</main>}>
      <AppShell>{content}</AppShell>
    </ShellFallback>
  );
}
