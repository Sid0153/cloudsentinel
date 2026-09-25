import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { getAbout } from "../services/about";
import type { About } from "../types/api";

// null until GET /api/about answers, and if it fails: the app then behaves as in normal mode
// (no guest button, no sandbox banner), which is always safe.
const AboutContext = createContext<About | null>(null);

export function AboutProvider({ children }: { children: ReactNode }) {
  const [about, setAbout] = useState<About | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAbout()
      .then((value) => {
        if (!cancelled) setAbout(value);
      })
      .catch(() => {
        // Keep null: normal mode.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return <AboutContext.Provider value={about}>{children}</AboutContext.Provider>;
}

export function useAbout(): About | null {
  return useContext(AboutContext);
}
