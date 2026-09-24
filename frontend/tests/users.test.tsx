import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { User } from "../src/types/auth";
import { callsTo } from "./mockApi";
import { renderAs } from "./renderApp";

// renderAs signs in with this ID (see tokenReply in mockApi.ts).
const SELF_ID = "11111111-1111-1111-1111-111111111111";

function user(overrides: Partial<User>): User {
  return {
    id: "22222222-2222-2222-2222-222222222222",
    email: "analyst@example.com",
    role: "ANALYST",
    is_active: true,
    created_at: "2026-01-01T00:00:00Z",
    last_login_at: null,
    ...overrides,
  };
}

const USERS = [user({ id: SELF_ID, email: "admin@example.com", role: "ADMIN" }), user({})];

describe("Users page", () => {
  it("lets an admin change another user's role and deactivate them", async () => {
    const { fetchMock } = renderAs("ADMIN", "/users", {
      "GET /api/users": { status: 200, body: USERS },
      "PATCH /api/users/22222222-2222-2222-2222-222222222222": { status: 200, body: user({}) },
    });
    fireEvent.change(await screen.findByLabelText("Role of analyst@example.com"), {
      target: { value: "VIEWER" },
    });
    await waitFor(() => expect(callsTo(fetchMock, "PATCH /api/users/22222222-2222-2222-2222-222222222222")).toBe(1));
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    await waitFor(() => expect(callsTo(fetchMock, "PATCH /api/users/22222222-2222-2222-2222-222222222222")).toBe(2));

    const bodies = fetchMock.mock.calls
      .filter(([, init]) => init?.method === "PATCH")
      .map(([, init]) => JSON.parse(String(init?.body)));
    expect(bodies).toEqual([{ role: "VIEWER" }, { is_active: false }]);
  });

  it("does not let admins change their own role or deactivate themselves", async () => {
    renderAs("ADMIN", "/users", { "GET /api/users": { status: 200, body: USERS } });
    expect(await screen.findByLabelText("Role of admin@example.com")).toBeDisabled();
    expect(screen.getAllByRole("button", { name: "Deactivate" })).toHaveLength(1); // only the other user
  });

  it("shows an error when the update fails", async () => {
    renderAs("ADMIN", "/users", {
      "GET /api/users": { status: 200, body: USERS },
      "PATCH /api/users/22222222-2222-2222-2222-222222222222": { status: 500 },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Deactivate" }));
    expect(await screen.findByText("Could not update this user.")).toBeInTheDocument();
  });
});
