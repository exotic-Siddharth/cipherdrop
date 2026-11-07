import { FileLock } from 'lucide-react';
import { PageHeader } from '../../components/layout/PageHeader';
import { Card } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/EmptyState';

/** Placeholder (S5). Lane W2 replaces this module; keep exporting `Component` (router lazy convention). */
export function Component() {
  return (
    <>
      <PageHeader
        title="Receive files"
        description="Files are decrypted in your browser with the key from the link."
      />
      <Card>
        <EmptyState
          icon={FileLock}
          title="Decryption happens here"
          description="Drop details, password prompt, decrypt and download, integrity verdicts and previews are built in lane W2."
        />
      </Card>
    </>
  );
}
