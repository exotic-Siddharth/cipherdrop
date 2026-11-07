import { LayoutDashboard } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W2 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Your drops, decrypted locally with your account key."
      />
      <Card>
        <EmptyState
          icon={LayoutDashboard}
          title="Your drops land here"
          description="The storage meter and the drop list with decrypted names are built in lane W2."
        />
      </Card>
    </>
  );
}
