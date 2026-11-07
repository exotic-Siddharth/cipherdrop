import { LogIn } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W1 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <div className="mx-auto max-w-md">
      <PageHeader title="Log in" description="Your password never leaves this device." />
      <Card>
        <EmptyState
          icon={LogIn}
          size="sm"
          title="Sign-in lands here"
          description="Local key derivation, TOTP and backup codes are built in lane W1."
        />
      </Card>
    </div>
  );
}
