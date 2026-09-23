import { useEffect, useState } from "react";

import { getReadiness } from "../services/health";
import type { HealthStatus } from "../types/health";

export type ReadinessState =
  | { kind: "loading" }
  | { kind: "loaded"; health: HealthStatus }
  | { kind: "error"; message: string };

export function useReadiness(): ReadinessState {
  const [state, setState] = useState<ReadinessState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    getReadiness()
      .then((health) => {
        if (!cancelled) setState({ kind: "loaded", health });
      })
      .catch(() => {
        if (!cancelled) setState({ kind: "error", message: "Could not reach the CloudSentinel API." });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
