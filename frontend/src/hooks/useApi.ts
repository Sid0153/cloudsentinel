import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "../services/api";

export type LoadState<T> =
  | { kind: "loading" }
  | { kind: "loaded"; data: T }
  | { kind: "error"; message: string };

export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "Your role does not have access to this.";
    if (error.status === 404) return "Not found. It may have been removed.";
    if (error.status === 401) return "Your session has expired. Please sign in again.";
  }
  return "Could not load data from the CloudSentinel API.";
}

/**
 * Runs `load` whenever `key` changes and returns its state.
 *
 * `reload()` fetches again but keeps showing the current data meanwhile (used for polling),
 * whereas a new `key` (for example new filters) shows the loading state.
 */
export function useApi<T>(load: () => Promise<T>, key: string) {
  const [state, setState] = useState<LoadState<T>>({ kind: "loading" });
  const [reloadCount, setReloadCount] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  const lastKey = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (lastKey.current !== key) {
      lastKey.current = key;
      setState({ kind: "loading" });
    }
    loadRef
      .current()
      .then((data) => {
        if (!cancelled) setState({ kind: "loaded", data });
      })
      .catch((error: unknown) => {
        if (!cancelled) setState({ kind: "error", message: describeError(error) });
      });
    return () => {
      cancelled = true;
    };
  }, [key, reloadCount]);

  const reload = useCallback(() => setReloadCount((count) => count + 1), []);
  return { state, reload, setState };
}
