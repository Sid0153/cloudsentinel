import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import App from "../src/App";
import { AuthProvider } from "../src/auth/AuthContext";
import type { Role } from "../src/types/auth";
import { dashboard } from "./fixtures";
import { mockFetchRoutes, tokenReply, type MockRoutes } from "./mockApi";

/** Renders the whole app (router + auth) at a path, signed in as a role. */
export function renderAs(role: Role, path: string, routes: MockRoutes = {}) {
  const fetchMock = mockFetchRoutes({
    "POST /api/auth/refresh": tokenReply(role, `${role.toLowerCase()}@example.com`),
    "GET /api/health/ready": { status: 200, body: { status: "ok", database: "up" } },
    "GET /api/dashboard/summary": { status: 200, body: dashboard() },
    "GET /api/aws-accounts": { status: 200, body: [] },
    "GET /api/about": {
      status: 200,
      body: { version: "0.1.0", sandbox_mode: false, guest_access: false },
    },
    ...routes,
  });
  const view = render(
    <AuthProvider>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </AuthProvider>,
  );
  return { fetchMock, ...view };
}
