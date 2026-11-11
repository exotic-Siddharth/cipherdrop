import { useCallback } from 'react';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';
import { useAuth } from '../../stores/auth';
import { useLeaveGuard } from '../../stores/leaveGuard';

/**
 * Explicit sign-out (navbar, account menu, the /unlock page's "Sign out"): leave guarded routes first, so the
 * route guards do not bounce to /login?next=..., then revoke the session server-side and lock the vault.
 * A running upload asks first (C-17): Stay keeps the session; confirming cancels the upload before logout.
 */
export function useSignOut(): () => Promise<void> {
  const navigate = useNavigate();
  const logout = useAuth((s) => s.logout);
  return useCallback(async () => {
    const confirmLeave = useLeaveGuard.getState().confirmLeave;
    if (confirmLeave && !(await confirmLeave())) return;
    await navigate('/');
    await logout('user');
    toast.success('Signed out', { id: 'signed-out' });
  }, [navigate, logout]);
}
