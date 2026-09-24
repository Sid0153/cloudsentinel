import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ACCOUNT, RULE, scan } from "./fixtures";
import { callsTo, requestedUrls } from "./mockApi";
import { renderAs } from "./renderApp";

const ACCOUNTS = { "GET /api/aws-accounts": { status: 200, body: [ACCOUNT] } };
const SCANS = {
  "GET /api/scans": { status: 200, body: [scan()], headers: { "X-Total-Count": "1" } },
};

afterEach(() => {
  vi.useRealTimers();
});

describe("Scans page", () => {
  it("lists scan history with status and counts", async () => {
    renderAs("VIEWER", "/scans", { ...ACCOUNTS, ...SCANS });
    expect(await screen.findByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("Production")).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "12" })).toBeInTheDocument();
  });

  it("does not offer scanning to viewers", async () => {
    renderAs("VIEWER", "/scans", { ...ACCOUNTS, ...SCANS });
    await screen.findByText("Completed");
    expect(screen.queryByRole("button", { name: "Start scan" })).not.toBeInTheDocument();
  });

  it("lets an analyst start a scan", async () => {
    const { fetchMock } = renderAs("ANALYST", "/scans", {
      ...ACCOUNTS,
      ...SCANS,
      "POST /api/scans": { status: 202, body: scan({ status: "PENDING" }) },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Start scan" }));
    await waitFor(() => expect(callsTo(fetchMock, "POST /api/scans")).toBe(1));
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST" && String(init.body).includes("aws_account_id"));
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ aws_account_id: ACCOUNT.id });
  });

  it("explains a conflict when a scan is already running", async () => {
    renderAs("ANALYST", "/scans", { ...ACCOUNTS, ...SCANS, "POST /api/scans": { status: 409 } });
    fireEvent.click(await screen.findByRole("button", { name: "Start scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already queued or running");
  });

  it("tells an analyst how to get an account when none is registered", async () => {
    renderAs("ANALYST", "/scans", { ...SCANS });
    expect(await screen.findByText(/Ask an admin to register one/)).toBeInTheDocument();
  });

  it("refreshes while a scan is running", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { fetchMock } = renderAs("VIEWER", "/scans", {
      ...ACCOUNTS,
      "GET /api/scans": { status: 200, body: [scan({ status: "RUNNING" })], headers: { "X-Total-Count": "1" } },
    });
    await screen.findByText("Running");
    const listCalls = () => requestedUrls(fetchMock, "GET", "/api/scans").length;
    const before = listCalls();
    expect(before).toBeGreaterThan(0);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3100);
    });
    await waitFor(() => expect(listCalls()).toBeGreaterThan(before));
  });
});

describe("Scan detail", () => {
  it("shows coverage, rule results and warns that incomplete is not secure", async () => {
    const detail = scan({ status: "COMPLETED_WITH_ERRORS" });
    renderAs("VIEWER", `/scans/${detail.id}`, {
      [`GET /api/scans/${detail.id}`]: { status: 200, body: detail },
      "GET /api/rules": { status: 200, body: [RULE] },
    });
    expect(await screen.findByText(/does not mean the resource is secure/)).toBeInTheDocument();
    expect(screen.getByText("AccessDenied (GetAccountAuthorizationDetails)")).toBeInTheDocument();
    expect(screen.getByText("Incomplete")).toBeInTheDocument();
    expect(screen.getByText(RULE.title)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "1" })).toHaveAttribute("href", "/findings?rule_id=CS-SG-001");
  });
});
