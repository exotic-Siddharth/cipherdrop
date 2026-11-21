/**
 * The key fragment of a receive link, taken out of the address bar (crypto-4).
 *
 * The page reads `#<key>` once, then replaces the current history entry with the same path and query and no
 * fragment, and keeps the fragment in that entry's history.state (React Router's location.state). The key
 * leaves the address bar, so it no longer shows in a screen share or in a URL copied from the address bar, while
 * a reload of this tab still opens the drop. forget() removes the history.state copy too, once nothing can use
 * it: the drop has no downloads left or is gone.
 *
 * What this does NOT do: the browser's global (and synced) history recorded the full URL, fragment included,
 * when the link was first opened, and replacing the entry does not remove that record. history.state can also
 * be written to the browser's session-restore files until forget() runs.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';

/** The location.state field that keeps the fragment for a reload of this tab. */
export const SHARE_FRAGMENT_STATE = 'shareFragment';

type State = Record<string, unknown>;

function asState(state: unknown): State {
  return state !== null && typeof state === 'object' ? (state as State) : {};
}

function fragmentIn(state: unknown): string {
  const value = asState(state)[SHARE_FRAGMENT_STATE];
  return typeof value === 'string' ? value : '';
}

function withoutFragment(state: unknown): State {
  const { [SHARE_FRAGMENT_STATE]: _dropped, ...rest } = asState(state);
  return rest;
}

export interface ShareFragment {
  /** The fragment as read from the link, `#` included ('' when the link had none). */
  fragment: string;
  /** Remove the reload copy from history.state (the page keeps its in-memory key). */
  forget: () => void;
}

export function useShareFragment(): ShareFragment {
  const { pathname, search, hash, state } = useLocation();
  const navigate = useNavigate();
  const [fragment, setFragment] = useState(() => hash || fragmentIn(state));
  // A fragment typed into the address bar later (a hash-only navigation) replaces the one read at mount.
  if (hash && hash !== fragment) setFragment(hash);
  // forget() may run before the effect below has stripped the fragment: never store a forgotten one.
  const forgotten = useRef<string | null>(null);

  useEffect(() => {
    if (!hash) return;
    const rest = withoutFragment(state);
    void navigate(
      { pathname, search },
      {
        replace: true,
        preventScrollReset: true,
        state: forgotten.current === hash ? rest : { ...rest, [SHARE_FRAGMENT_STATE]: hash },
      },
    );
  }, [navigate, pathname, search, hash, state]);

  const forget = useCallback(() => {
    forgotten.current = fragment;
    if (!hash && !fragmentIn(state)) return;
    void navigate(
      { pathname, search },
      { replace: true, preventScrollReset: true, state: withoutFragment(state) },
    );
  }, [navigate, pathname, search, hash, state, fragment]);

  return { fragment, forget };
}
