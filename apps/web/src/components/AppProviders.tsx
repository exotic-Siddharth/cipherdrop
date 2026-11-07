import { QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { Toaster } from 'sonner';
import { queryClient } from '../lib/queryClient';
import { useTheme } from '../stores/theme';

/** App-wide providers: TanStack Query (shared client, R22 retry policy) and the toast region. */
export function AppProviders({ children }: { children: ReactNode }) {
  const theme = useTheme((s) => s.resolved);
  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <Toaster
        theme={theme}
        position="bottom-right"
        closeButton
        toastOptions={{ classNames: { toast: 'font-sans', description: 'text-[13px]' } }}
      />
    </QueryClientProvider>
  );
}
