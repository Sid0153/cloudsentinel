import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import App from "../src/App";
import { AuthProvider } from "../src/auth/AuthContext";
import { dashboard } from "./fixtures";
import { callsTo, mockFetchRoutes, tokenReply, type MockRoutes } from "./mockApi";

const HEALTH = {
  "GET /api/health/ready": { status: 200, body: { status: "ok", database: "up" } },
  "GET /api/dashboard/summary": { status: 200, body: dashboard() },
  "GET /api/aws-accounts": { status: 200, body: [] },
};

function renderApp(path: string) {
  return render(
    <AuthProvider>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </AuthProvider>,
  );
}

function signedInAs(role: "ADMIN" | "ANALYST" | "VIEWER", extra: MockRoutes = {}) {
  return mockFetchRoutes({
    "POST /api/auth/refresh": tokenReply(role, `${role.toLowerCase()}@example.com`),
    ...HEALTH,
    ...extra,
  });
}

describe("route protection", () => {
  it("redirects an anonymous visitor to the login page", async () => {
    mockFetchRoutes({ "POST /api/auth/refresh": { status: 401 } });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("restores a session from the refresh cookie", async () => {
    signedInAs("VIEWER");
    renderApp("/");
    expect(await screen.findByText("viewer@example.com")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("shows the Users link to admins only", async () => {
    signedInAs("VIEWER");
    const first = renderApp("/");
    await screen.findByText("viewer@example.com");
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    first.unmount();

    signedInAs("ADMIN", { "GET /api/users": { status: 200, body: [] } });
    renderApp("/");
    expect(await screen.findByRole("link", { name: "Users" })).toBeInTheDocument();
  });

  it("blocks a viewer from the admin page without calling the users API", async () => {
    const fetchMock = signedInAs("VIEWER");
    renderApp("/users");
    expect(await screen.findByRole("heading", { name: "Not authorized" })).toBeInTheDocument();
    expect(callsTo(fetchMock, "GET /api/users")).toBe(0);
  });

  it("lets an admin see the user list", async () => {
    signedInAs("ADMIN", {
      "GET /api/users": {
        status: 200,
        body: [
          {
            id: "22222222-2222-2222-2222-222222222222",
            email: "other@example.com",
            role: "ANALYST",
            is_active: true,
            created_at: "2026-01-01T00:00:00Z",
            last_login_at: null,
          },
        ],
      },
    });
    renderApp("/users");
    expect(await screen.findByText("other@example.com")).toBeInTheDocument();
  });

  it("shows the not-found page for unknown routes when signed in", async () => {
    signedInAs("VIEWER");
    renderApp("/does-not-exist");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});

describe("signing in and out", () => {
  it("signs in with valid credentials", async () => {
    mockFetchRoutes({
      "POST /api/auth/refresh": { status: 401 },
      "POST /api/auth/login": tokenReply("ANALYST", "analyst@example.com"),
      ...HEALTH,
    });
    renderApp("/login");
    fireEvent.change(await screen.findByLabelText("Email"), {
      target: { value: "analyst@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a-long-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();
  });

  it("shows a message for wrong credentials", async () => {
    mockFetchRoutes({
      "POST /api/auth/refresh": { status: 401 },
      "POST /api/auth/login": { status: 401, body: { detail: "Invalid email or password" } },
    });
    renderApp("/login");
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "a@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect email or password");
  });

  it("shows a message when rate limited", async () => {
    mockFetchRoutes({
      "POST /api/auth/refresh": { status: 401 },
      "POST /api/auth/login": { status: 429, body: {} },
    });
    renderApp("/login");
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "a@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Too many attempts");
  });

  it("signs out and returns to the login page", async () => {
    const fetchMock = signedInAs("VIEWER", { "POST /api/auth/logout": { status: 204 } });
    renderApp("/");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(callsTo(fetchMock, "POST /api/auth/logout")).toBe(1);
  });
});
