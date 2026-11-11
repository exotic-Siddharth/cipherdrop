import { AutoLockCard } from './AutoLockCard';
import { PasswordCard } from './PasswordCard';
import { RecoveryRotationCard } from './RecoveryRotationCard';
import { TwoFactorCard } from './TwoFactorCard';

export function SecurityTab() {
  return (
    <div className="flex flex-col gap-6">
      <TwoFactorCard />
      <PasswordCard />
      <RecoveryRotationCard />
      <AutoLockCard />
    </div>
  );
}
