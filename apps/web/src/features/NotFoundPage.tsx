import { CircleHelp, FileQuestion, Send } from 'lucide-react';
import { ButtonLink } from '../components/ui/Button';
import { EmptyState } from '../components/ui/EmptyState';

/** 404 for unknown paths (route "*"). S5-owned. */
export function Component() {
  return (
    <EmptyState
      icon={FileQuestion}
      titleAs="h1"
      title="Page not found"
      description="There is nothing at this address. If someone sent you a CipherDrop link, check that you copied all of it."
      action={
        <>
          <ButtonLink to="/" icon={Send}>
            Send files
          </ButtonLink>
          <ButtonLink to="/how-it-works" variant="outline" icon={CircleHelp}>
            How it works
          </ButtonLink>
        </>
      }
    />
  );
}
