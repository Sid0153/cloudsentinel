import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { tokenStore } from "../src/services/tokenStore";

// Vitest globals are off, so Testing Library cannot register its own cleanup.
afterEach(() => {
  cleanup();
  tokenStore.set(null);
  vi.unstubAllGlobals();
});
