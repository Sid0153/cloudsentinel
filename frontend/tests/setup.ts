import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { resetSlowRequests } from "../src/services/http";
import { tokenStore } from "../src/services/tokenStore";

// The first test in a file also pays for compiling the app. On a cold CI runner that can take
// longer than Testing Library's default 1 s wait, which made first tests flaky.
configure({ asyncUtilTimeout: 5000 });

// Vitest globals are off, so Testing Library cannot register its own cleanup.
afterEach(() => {
  cleanup();
  tokenStore.set(null);
  resetSlowRequests();
  vi.unstubAllGlobals();
});
