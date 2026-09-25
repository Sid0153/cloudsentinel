import { useSyncExternalStore } from "react";

import { requestsAreSlow, subscribeToSlowRequests } from "../services/http";

/** Shown while any API request takes more than a few seconds, for example while a stopped
 * backend on a free hosting plan starts up again. */
export default function ServerWakeNotice() {
  const slow = useSyncExternalStore(subscribeToSlowRequests, requestsAreSlow);
  if (!slow) return null;
  return (
    <div
      role="status"
      className="fixed inset-x-0 bottom-0 z-10 border-t border-amber-300 bg-amber-50 px-4 py-3 text-center text-sm text-amber-900"
    >
      The server is taking a while to answer. If nobody has used it for a while it is starting
      up, which can take two or three minutes. This page will continue by itself.
    </div>
  );
}
