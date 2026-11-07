import { useCallback } from 'react';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';
import { useAuth } from '../../stores/auth';

/**
 * Explicit sign-out (navbar, account menu, the /unlock page's "Sign out"): leave guarded routes first, so the
 * route guards do not bounce to /login?next=..., then revoke the session server-side and lock the vault.
 */
export function useSignOut(): () => Promise<void> {
  const navigate = useNavigate();
  const logout = useAuth((s) => s.logout);
  return useCallback(async () => {
    await navigate('/');
    await logout('user');
    toast.success('Signed out', { id: 'signed-out' });
  }, [navigate, logout]);
}
