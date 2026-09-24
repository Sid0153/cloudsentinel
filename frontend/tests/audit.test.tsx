import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AuditLogEntry } from "../src/types/api";
import { callsTo, requestedUrls } from "./mockApi";
import { renderAs } from "./renderApp";

function entry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    id: crypto.randomUUID(),
    created_at: "2026-09-24T10:00:00Z",
    action: "LOGIN_SUCCEEDED",
    outcome: "SUCCESS",
    actor_id: "u1",
    actor_email: "admin@example.com",
    target_type: "USER",
    target_id: "u1",
    ip_address: "203.0.113.7",
    request_id: "req-1",
    details: {},
    ...overrides,
  };
}

const ENTRIES = [
  entry({
    action: "LOGIN_FAILED",
    outcome: "FAILURE",
    actor_id: null,
    actor_email: null,
    target_type: null,
    target_id: null,
    details: { reason: "unknown_email" },
  }),
  entry({
    action: "SCAN_COMPLETED",
    actor_id: null,
    actor_email: null,
    target_type: "SCAN",
    target_id: "s1",
    details: { status: "COMPLETED", finding_count: 7 },
  }),
  entry({
    action: "FINDING_STATUS_CHANGED",
    actor_email: "analyst@example.com",
    target_type: "FINDING",
    target_id: "f1",
    details: { from: "OPEN", to: "ACKNOWLEDGED", note: "<img src=x onerror=alert(1)>" },
  }),
];

const LOG = { "GET /api/audit-logs": { status: 200, body: ENTRIES, headers: { "X-Total-Count": "3" } } };

describe("Audit log page", () => {
  it("lists events with actor, outcome, target links and details", async () => {
    renderAs("ADMIN", "/audit", LOG);
    expect(await screen.findByRole("heading", { name: "Audit log" })).toBeInTheDocument();
    expect(await screen.findByText("Login failed")).toBeInTheDocument();
    expect(screen.getByText("Anonymous")).toBeInTheDocument(); // failed login: nobody signed in
    expect(screen.getByText("System")).toBeInTheDocument(); // scan completion
    expect(screen.getByText("analyst@example.com")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Scan" })).toHaveAttribute("href", "/scans/s1");
    expect(screen.getByRole("link", { name: "Finding" })).toHaveAttribute("href", "/findings/f1");
    expect(screen.getByText("unknown_email")).toBeInTheDocument();
    expect(screen.getByText("1–3 of 3")).toBeInTheDocument();
  });

  it("shows details as text, never as HTML", async () => {
    const { container } = renderAs("ADMIN", "/audit", LOG);
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("filters by action and outcome through the API", async () => {
    const { fetchMock } = renderAs("ADMIN", "/audit", LOG);
    await screen.findByText("Login failed");
    const filters = screen.getAllByRole("combobox");
    fireEvent.change(filters[0], { target: { value: "ACCESS_DENIED" } });
    await waitFor(() =>
      expect(requestedUrls(fetchMock, "GET", "/api/audit-logs").at(-1)).toContain("action=ACCESS_DENIED"),
    );
    fireEvent.change(filters[1], { target: { value: "FAILURE" } });
    await waitFor(() =>
      expect(requestedUrls(fetchMock, "GET", "/api/audit-logs").at(-1)).toContain("outcome=FAILURE"),
    );
  });

  it("shows empty and error states", async () => {
    const empty = renderAs("ADMIN", "/audit", {
      "GET /api/audit-logs": { status: 200, body: [], headers: { "X-Total-Count": "0" } },
    });
    expect(await screen.findByText("No events match these filters.")).toBeInTheDocument();
    empty.unmount();

    renderAs("ADMIN", "/audit", { "GET /api/audit-logs": { status: 500 } });
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load data");
  });

  it("is admin only: other roles see no link and never call the API", async () => {
    const { fetchMock } = renderAs("ANALYST", "/audit", LOG);
    expect(await screen.findByRole("heading", { name: "Not authorized" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Audit log" })).not.toBeInTheDocument();
    expect(callsTo(fetchMock, "GET /api/audit-logs")).toBe(0);
    expect(requestedUrls(fetchMock, "GET", "/api/audit-logs")).toHaveLength(0);
  });
});
