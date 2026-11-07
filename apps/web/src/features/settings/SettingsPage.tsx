import { Settings } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W1 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Security, sessions, activity and account management."
      />
      <Card>
        <EmptyState
          icon={Settings}
          title="Settings land here"
          description="Two-factor authentication, sessions, the activity log and account deletion are built in lane W1."
        />
      </Card>
    </>
  );
}
