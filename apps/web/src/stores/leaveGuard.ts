/**
 * Sign-out guard (C-17): signing out ends the session the running upload belongs to, but on "/" its first
 * navigate('/') does not leave the Send page, so the router blocker never asks. While an upload runs, the
 * Send page registers `confirmLeave` here; useSignOut awaits it and signs out only when it resolves true
 * (the page has cancelled the upload by then).
 */
import { create } from 'zustand';

interface LeaveGuardState {
  confirmLeave: (() => Promise<boolean>) | null;
}

export const useLeaveGuard = create<LeaveGuardState>(() => ({ confirmLeave: null }));
