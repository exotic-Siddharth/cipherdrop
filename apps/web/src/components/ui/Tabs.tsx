import type { LucideIcon } from 'lucide-react';
import {
  createContext,
  useContext,
  useId,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { cn } from '../../lib/cn';

type TabsVariant = 'underline' | 'pills';

interface TabsContextValue {
  baseId: string;
  value: string;
  setValue: (value: string) => void;
  variant: TabsVariant;
}

const TabsContext = createContext<TabsContextValue | null>(null);

function useTabsContext(): TabsContextValue {
  const ctx = useContext(TabsContext);
  if (!ctx) throw new Error('TabsList, TabsTrigger and TabsContent must be rendered inside <Tabs>');
  return ctx;
}

const slug = (value: string) => value.replace(/[^A-Za-z0-9_-]/g, '_');

export interface TabsProps {
  /** Controlled value (pair with onValueChange), e.g. synced to ?tab= in the URL. */
  value?: string;
  /** Uncontrolled initial value. One of value/defaultValue must match a TabsTrigger. */
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  /** 'underline' for page sections (Settings), 'pills' for filters (Active / Expired / All). */
  variant?: TabsVariant;
  className?: string;
  children: ReactNode;
}

/**
 * Accessible tabs (WAI-ARIA tabs pattern, automatic activation): Arrow Left/Right, Home and End move between
 * tabs. Compose with TabsList > TabsTrigger and TabsContent.
 */
export function Tabs({
  value,
  defaultValue,
  onValueChange,
  variant = 'underline',
  className,
  children,
}: TabsProps) {
  const baseId = useId();
  const [inner, setInner] = useState(defaultValue ?? '');
  const current = value ?? inner;
  const setValue = (next: string) => {
    if (value === undefined) setInner(next);
    onValueChange?.(next);
  };
  return (
    <TabsContext.Provider value={{ baseId, value: current, setValue, variant }}>
      <div className={className}>{children}</div>
    </TabsContext.Provider>
  );
}

export interface TabsListProps {
  /** Accessible name of the tab list, e.g. "Settings sections". */
  'aria-label'?: string;
  className?: string;
  children: ReactNode;
}

export function TabsList({ className, children, 'aria-label': ariaLabel }: TabsListProps) {
  const { variant } = useTabsContext();
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const tabs = Array.from(
      e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]:not([disabled])'),
    );
    const index = tabs.indexOf(document.activeElement as HTMLButtonElement);
    if (index < 0 || tabs.length === 0) return;
    let next = -1;
    if (e.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    tabs[next]?.focus();
    tabs[next]?.click();
  };
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      aria-orientation="horizontal"
      onKeyDown={onKeyDown}
      className={cn(
        variant === 'underline'
          ? 'flex gap-1 overflow-x-auto border-b border-border'
          : 'inline-flex max-w-full items-center gap-1 overflow-x-auto rounded-lg border border-border bg-surface-2 p-1',
        className,
      )}
    >
      {children}
    </div>
  );
}

export interface TabsTriggerProps {
  value: string;
  icon?: LucideIcon;
  /** Trailing element such as a count Badge. */
  badge?: ReactNode;
  disabled?: boolean;
  className?: string;
  children: ReactNode;
}

export function TabsTrigger({
  value,
  icon: Icon,
  badge,
  disabled = false,
  className,
  children,
}: TabsTriggerProps) {
  const { baseId, value: current, setValue, variant } = useTabsContext();
  const selected = current === value;
  return (
    <button
      type="button"
      role="tab"
      id={`${baseId}-tab-${slug(value)}`}
      aria-controls={`${baseId}-panel-${slug(value)}`}
      aria-selected={selected}
      tabIndex={selected ? 0 : -1}
      disabled={disabled}
      onClick={() => setValue(value)}
      className={cn(
        'inline-flex shrink-0 items-center gap-2 whitespace-nowrap text-sm font-medium transition-colors',
        'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:opacity-50',
        variant === 'underline'
          ? cn(
              '-mb-px border-b-2 px-3 py-2.5',
              selected
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-strong hover:border-border-strong hover:text-foreground',
            )
          : cn(
              'rounded-md px-3 py-1.5',
              selected
                ? 'bg-surface text-foreground shadow-card'
                : 'text-muted-strong hover:text-foreground',
            ),
        className,
      )}
    >
      {Icon ? <Icon className="size-4" aria-hidden="true" /> : null}
      {children}
      {badge}
    </button>
  );
}

export interface TabsContentProps {
  value: string;
  className?: string;
  children: ReactNode;
}

/** The panel of `value`; rendered only while that tab is selected. */
export function TabsContent({ value, className, children }: TabsContentProps) {
  const { baseId, value: current } = useTabsContext();
  if (current !== value) return null;
  return (
    <div
      role="tabpanel"
      id={`${baseId}-panel-${slug(value)}`}
      aria-labelledby={`${baseId}-tab-${slug(value)}`}
      tabIndex={0}
      className={cn(
        'focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-primary',
        className,
      )}
    >
      {children}
    </div>
  );
}
