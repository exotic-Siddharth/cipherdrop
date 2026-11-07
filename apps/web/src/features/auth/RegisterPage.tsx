import { UserRound } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W1 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <div className="mx-auto max-w-md">
      <PageHeader
        title="Create account"
        description="A zero-knowledge account: we store keys wrapped by your password, never the password."
      />
      <Card>
        <EmptyState
          icon={UserRound}
          size="sm"
          title="Registration lands here"
          description="Key derivation and the recovery-key step are built in lane W1."
        />
      </Card>
    </div>
  );
}
