import { QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Toaster } from 'sonner';
import { queryClient } from '../lib/queryClient';
import { useTheme } from '../stores/theme';

/** App-wide providers: TanStack Query (shared client, R22 retry policy) and the toast region. */
export function AppProviders({ children }: { children: ReactNode }) {
  const theme = useTheme((s) => s.resolved);
  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {/* Outside #root: Dialog makes #root inert while open, and toasts raised then must stay reachable. */}
      {createPortal(
        <Toaster
          theme={theme}
          position="bottom-right"
          closeButton
          toastOptions={{ classNames: { toast: 'font-sans', description: 'text-[13px]' } }}
        />,
        document.body,
      )}
    </QueryClientProvider>
  );
}
