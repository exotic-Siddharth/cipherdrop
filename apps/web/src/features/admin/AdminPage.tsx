import { ShieldCheck } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/**
 * Placeholder (S5). Lane W2 replaces this module; keep exporting `Component` (router lazy convention).
 * It renders inside AdminLayout behind RequireAdmin.
 */
export function Component() {
  return (
    <>
      <PageHeader
        title="Admin"
        description="Statistics, abuse reports and users."
        className="mb-0"
      />
      <Card>
        <EmptyState
          icon={ShieldCheck}
          title="Moderation tools land here"
          description="Stats with the uploads chart, the report queue and user management are built in lane W2."
        />
      </Card>
    </>
  );
}
