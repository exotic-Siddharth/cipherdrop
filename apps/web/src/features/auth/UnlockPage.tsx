import { Lock } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W1 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Unlock vault"
        description="Enter your password to unlock your account key on this device."
      />
      <Card>
        <EmptyState
          icon={Lock}
          size="sm"
          title="Vault unlock lands here"
          description="The local password unwrap is built in lane W1."
        />
      </Card>
    </div>
  );
}
