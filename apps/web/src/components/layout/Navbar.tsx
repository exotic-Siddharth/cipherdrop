import type { Me } from '@cipherdrop/shared';
import {
  ChevronDown,
  CircleHelp,
  LayoutDashboard,
  Lock,
  LockOpen,
  LogOut,
  Menu,
  Send,
  Settings,
  ShieldCheck,
  X,
  type LucideIcon,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router';
import { toast } from 'sonner';
import { cn } from '../../lib/cn';
import { unlockPath } from '../../lib/paths';
import { useAuth, type AuthStatus } from '../../stores/auth';
import { useVault } from '../../stores/vault';
import { Button, ButtonLink } from '../ui/Button';
import { DropdownMenu, type DropdownMenuEntry } from '../ui/DropdownMenu';
import { Skeleton } from '../ui/Skeleton';
import { Tooltip } from '../ui/Tooltip';
import { Logo } from './Logo';
import { ThemeToggle } from './ThemeToggle';
import { useSignOut } from './useSignOut';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

function navItems(user: Me | null): NavItem[] {
  const items: NavItem[] = [
    { to: '/', label: 'Send', icon: Send, end: true },
    { to: '/how-it-works', label: 'How it works', icon: CircleHelp },
  ];
  if (user) items.push({ to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard });
  if (user?.role === 'ADMIN') items.push({ to: '/admin', label: 'Admin', icon: ShieldCheck });
  return items;
}

function Avatar({ email }: { email: string }) {
  return (
    <span
      aria-hidden="true"
      className="inline-flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-sm font-semibold uppercase text-primary-ink"
    >
      {email.slice(0, 1) || '?'}
    </span>
  );
}

/** Lock state of the vault (the in-memory account key) with a one-click lock / unlock. */
function VaultStatus() {
  const unlocked = useVault((s) => s.accountKey !== null);
  const lock = useVault((s) => s.lock);
  const { pathname, search } = useLocation();

  if (unlocked) {
    return (
      <Tooltip content="Vault unlocked: your file names are readable on this device." side="bottom">
        <Button
          variant="ghost"
          size="sm"
          icon={LockOpen}
          aria-label="Lock vault"
          className="text-primary-ink"
          onClick={() => {
            lock('manual');
            toast.success('Vault locked', {
              description: 'Your account key was removed from this tab.',
            });
          }}
        >
          <span className="hidden lg:inline">Lock</span>
        </Button>
      </Tooltip>
    );
  }
  if (pathname === '/unlock') return null;
  return (
    <Tooltip content="Vault locked: unlock it to read your file names." side="bottom">
      <ButtonLink
        to={unlockPath(`${pathname}${search}`)}
        variant="ghost"
        size="sm"
        icon={Lock}
        aria-label="Unlock vault"
      >
        <span className="hidden lg:inline">Unlock</span>
      </ButtonLink>
    </Tooltip>
  );
}

function AccountMenu({ user }: { user: Me }) {
  const signOut = useSignOut();
  const unlocked = useVault((s) => s.accountKey !== null);
  const lock = useVault((s) => s.lock);
  const items: DropdownMenuEntry[] = [
    { label: 'Dashboard', icon: LayoutDashboard, to: '/dashboard' },
    { label: 'Settings', icon: Settings, to: '/settings' },
  ];
  if (user.role === 'ADMIN')
    items.push({ label: 'Admin console', icon: ShieldCheck, to: '/admin' });
  items.push({ type: 'separator' });
  if (unlocked) items.push({ label: 'Lock vault', icon: Lock, onSelect: () => lock('manual') });
  items.push({ label: 'Sign out', icon: LogOut, tone: 'danger', onSelect: () => void signOut() });
  return (
    <DropdownMenu
      label={`${user.email} account menu`}
      triggerVariant="ghost"
      triggerClassName="gap-2 pl-1.5 pr-2"
      trigger={
        <>
          <Avatar email={user.email} />
          <span className="hidden max-w-44 truncate lg:inline">{user.email}</span>
          <ChevronDown className="size-4 text-muted" aria-hidden="true" />
        </>
      }
      header={
        <>
          <p className="text-xs text-muted">Signed in as</p>
          <p className="truncate font-medium text-foreground">{user.email}</p>
        </>
      }
      items={items}
    />
  );
}

const desktopLinkClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    'inline-flex h-9 items-center rounded-lg px-3 text-sm font-medium transition-colors',
    isActive
      ? 'bg-primary/10 text-primary-ink'
      : 'text-muted-strong hover:bg-surface-2 hover:text-foreground',
  );

const mobileLinkClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    'flex h-11 items-center gap-3 rounded-lg px-3 text-[0.95rem] font-medium transition-colors',
    isActive ? 'bg-primary/10 text-primary-ink' : 'text-foreground hover:bg-surface-2',
  );

function MobileNav({
  id,
  items,
  user,
  status,
}: {
  id: string;
  items: NavItem[];
  user: Me | null;
  status: AuthStatus;
}) {
  const signOut = useSignOut();
  return (
    <div id={id} className="border-t border-border bg-background md:hidden">
      <nav aria-label="Main" className="mx-auto max-w-6xl px-4 py-3 sm:px-6">
        <ul className="flex flex-col gap-1">
          {items.map(({ to, label, icon: Icon, end }) => (
            <li key={to}>
              <NavLink to={to} end={end} className={mobileLinkClass}>
                <Icon className="size-5 text-muted" aria-hidden="true" />
                {label}
              </NavLink>
            </li>
          ))}
          {user ? (
            <li>
              <NavLink to="/settings" className={mobileLinkClass}>
                <Settings className="size-5 text-muted" aria-hidden="true" />
                Settings
              </NavLink>
            </li>
          ) : null}
        </ul>
        <div className="mt-3 border-t border-border pt-3">
          {status === 'booting' ? (
            <Skeleton className="h-10 w-full" />
          ) : user ? (
            <div className="flex items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2">
                <Avatar email={user.email} />
                <span className="truncate text-sm text-foreground">{user.email}</span>
              </div>
              <Button variant="outline" size="sm" icon={LogOut} onClick={() => void signOut()}>
                Sign out
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              <ButtonLink to="/login" variant="outline">
                Log in
              </ButtonLink>
              <ButtonLink to="/register">Sign up</ButtonLink>
            </div>
          )}
        </div>
      </nav>
    </div>
  );
}

/** Top bar: logo, main links, vault status, theme toggle and the account menu (or Log in / Sign up). */
export function Navbar() {
  const status = useAuth((s) => s.status);
  const user = useAuth((s) => s.user);
  const items = navItems(user);
  const [menuOpen, setMenuOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const { pathname } = useLocation();

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!menuOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMenuOpen(false);
        toggleRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [menuOpen]);

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-background/85 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-2 px-4 sm:px-6">
        <Link
          to="/"
          aria-label="CipherDrop home"
          className="mr-3 rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-primary"
        >
          <Logo />
        </Link>
        <nav aria-label="Main" className="hidden md:block">
          <ul className="flex items-center gap-1">
            {items.map(({ to, label, end }) => (
              <li key={to}>
                <NavLink to={to} end={end} className={desktopLinkClass}>
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="ml-auto flex items-center gap-1">
          {status === 'authenticated' ? <VaultStatus /> : null}
          <ThemeToggle />
          <div className="hidden items-center gap-2 md:flex">
            {status === 'booting' ? (
              <Skeleton className="h-9 w-40" />
            ) : user ? (
              <AccountMenu user={user} />
            ) : (
              <>
                <ButtonLink to="/login" variant="ghost" size="sm">
                  Log in
                </ButtonLink>
                <ButtonLink to="/register" size="sm">
                  Sign up
                </ButtonLink>
              </>
            )}
          </div>
          <Button
            ref={toggleRef}
            variant="ghost"
            size="icon"
            className="md:hidden"
            icon={menuOpen ? X : Menu}
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            onClick={() => setMenuOpen((open) => !open)}
          />
        </div>
      </div>
      {menuOpen ? <MobileNav id="mobile-nav" items={items} user={user} status={status} /> : null}
    </header>
  );
}
