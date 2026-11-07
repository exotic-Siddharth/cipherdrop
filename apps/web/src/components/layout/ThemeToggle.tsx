import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../../stores/theme';
import { Button } from '../ui/Button';
import { Tooltip } from '../ui/Tooltip';

/** Light/dark switch (the preference persists in localStorage; theme-init.js applies it before paint). */
export function ThemeToggle({ className }: { className?: string }) {
  const resolved = useTheme((s) => s.resolved);
  const toggle = useTheme((s) => s.toggle);
  const next = resolved === 'dark' ? 'light' : 'dark';
  return (
    <Tooltip content={`Switch to ${next} theme`} side="bottom">
      <Button
        variant="ghost"
        size="icon"
        icon={resolved === 'dark' ? Sun : Moon}
        aria-label={`Switch to ${next} theme`}
        onClick={toggle}
        className={className}
      />
    </Tooltip>
  );
}
