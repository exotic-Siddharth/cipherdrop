import { KeyRound } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W1 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Recover account"
        description="Use your recovery key to set a new password."
      />
      <Card>
        <EmptyState
          icon={KeyRound}
          size="sm"
          title="Account recovery lands here"
          description="Recovery-key sign-in and key rotation are built in lane W1."
        />
      </Card>
    </div>
  );
}
