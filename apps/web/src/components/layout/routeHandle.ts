/** `handle` of every route in router.tsx. RootLayout turns `title` into document.title. */
export interface RouteHandle {
  title?: string;
}

export const APP_NAME = 'CipherDrop';

export function documentTitle(title: string | undefined): string {
  return title ? `${title} · ${APP_NAME}` : `${APP_NAME}: zero-knowledge file sharing`;
}
