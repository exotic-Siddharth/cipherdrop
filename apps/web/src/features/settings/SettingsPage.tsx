import { useSearchParams } from 'react-router';
import { PageHeader } from '../../components/layout/PageHeader';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/Tabs';
import { AccountTab } from './AccountTab';
import { ActivityTab } from './ActivityTab';
import { SecurityTab } from './SecurityTab';
import { SessionsTab } from './SessionsTab';

const TABS = ['security', 'sessions', 'activity', 'account'] as const;
type TabId = (typeof TABS)[number];

function isTab(value: string | null): value is TabId {
  return TABS.includes(value as TabId);
}

export function Component() {
  const [params, setParams] = useSearchParams();
  const requested = params.get('tab');
  const tab: TabId = isTab(requested) ? requested : 'security';

  return (
    <>
      <PageHeader
        title="Settings"
        description="Security, sessions, activity and account management."
      />
      <Tabs
        value={tab}
        onValueChange={(next) => {
          setParams(
            (prev) => {
              const copy = new URLSearchParams(prev);
              if (next === 'security') copy.delete('tab');
              else copy.set('tab', next);
              return copy;
            },
            { replace: true },
          );
        }}
      >
        <TabsList aria-label="Settings sections">
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
        </TabsList>
        <TabsContent value="security" className="pt-6">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="sessions" className="pt-6">
          <SessionsTab />
        </TabsContent>
        <TabsContent value="activity" className="pt-6">
          <ActivityTab />
        </TabsContent>
        <TabsContent value="account" className="pt-6">
          <AccountTab />
        </TabsContent>
      </Tabs>
    </>
  );
}
