import '@fontsource-variable/inter';
import '@fontsource-variable/jetbrains-mono';
import './styles/index.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router/dom';
import { AppProviders } from './components/AppProviders';
import { createAppRouter } from './router';
import { startSessionSync, useAuth } from './stores/auth';
import { useServerConfig } from './stores/serverConfig';
import { startThemeSync } from './stores/theme';
import { startVaultAutoLock } from './stores/vault';

// Boot (spec 11.3): one silent refresh, shared with the API client's 401 path (single-flight). The access
// token stays in memory; a reload therefore always starts with a locked vault.
void useAuth.getState().refresh();
// The operator switches (anonymous uploads, registration), so pages can explain a closed door up front.
void useServerConfig.getState().load();
startVaultAutoLock();
startThemeSync();
// Lock vault and sign-out apply to every open tab of this browser (critic-8).
startSessionSync();

const container = document.getElementById('root');
if (!container) throw new Error('index.html is missing <div id="root">');

createRoot(container).render(
  <StrictMode>
    <AppProviders>
      <RouterProvider router={createAppRouter()} />
    </AppProviders>
  </StrictMode>,
);
