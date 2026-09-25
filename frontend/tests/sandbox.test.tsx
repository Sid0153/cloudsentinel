import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";

import App from "../src/App";
import { AuthProvider } from "../src/auth/AuthContext";
import { setSlowRequestThreshold } from "../src/services/http";
import type { SandboxControl, SandboxState } from "../src/types/api";
import { dashboard } from "./fixtures";
import { PENDING, callsTo, mockFetchRoutes, tokenReply, type MockRoutes } from "./mockApi";
import { renderAs } from "./renderApp";

const SANDBOX_ON = {
  "GET /api/about": {
    status: 200,
    body: { version: "0.1.0", sandbox_mode: true, guest_access: true },
  },
};

function control(key: string, insecure: boolean, extra: Partial<SandboxControl> = {}): SandboxControl {
  return {
    key,
    title: key === "ssh-open" ? "SSH open to the internet" : "Remote Desktop open to the internet",
    description: "Security group sandbox-bastion allows the port from anywhere.",
    rule_id: key === "ssh-open" ? "CS-SG-001" : "CS-SG-002",
    insecure,
    insecure_by_default: key === "ssh-open",
    ...extra,
  };
}

function sandboxState(sshInsecure = true, rdpInsecure = false): SandboxState {
  return {
    account_id: "123456789012",
    region: "us-east-1",
    controls: [control("ssh-open", sshInsecure), control("rdp-open", rdpInsecure)],
  };
}

function renderLogin(routes: MockRoutes) {
  const fetchMock = mockFetchRoutes({
    "POST /api/auth/refresh": { status: 401 },
    "GET /api/health/ready": { status: 200, body: { status: "ok", database: "up" } },
    "GET /api/dashboard/summary": { status: 200, body: dashboard() },
    "GET /api/aws-accounts": { status: 200, body: [] },
    ...routes,
  });
  render(
    <AuthProvider>
      <MemoryRouter initialEntries={["/login"]}>
        <App />
      </MemoryRouter>
    </AuthProvider>,
  );
  return fetchMock;
}

describe("guest access", () => {
  it("offers 'Explore as guest' and signs in without a password", async () => {
    const fetchMock = renderLogin({
      ...SANDBOX_ON,
      "POST /api/auth/guest": tokenReply("ANALYST", "guest@cloudsentinel.example"),
    });
    fireEvent.click(await screen.findByRole("button", { name: "Explore as guest" }));
    expect(await screen.findByText("guest@cloudsentinel.example")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    expect(callsTo(fetchMock, "POST /api/auth/guest")).toBe(1);
    expect(callsTo(fetchMock, "POST /api/auth/login")).toBe(0);
  });

  it("explains when guest access is refused", async () => {
    renderLogin({ ...SANDBOX_ON, "POST /api/auth/guest": { status: 403 } });
    fireEvent.click(await screen.findByRole("button", { name: "Explore as guest" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Guest access is not available");
  });

  it("shows no guest button or demo note in normal mode", async () => {
    renderLogin({
      "GET /api/about": {
        status: 200,
        body: { version: "0.1.0", sandbox_mode: false, guest_access: false },
      },
    });
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    await screen.findByLabelText("Email");
    expect(screen.queryByRole("button", { name: "Explore as guest" })).not.toBeInTheDocument();
    expect(screen.queryByText(/simulated AWS account/)).not.toBeInTheDocument();
  });

  it("falls back to normal mode when /api/about fails", async () => {
    renderLogin({ "GET /api/about": { status: 500 } });
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Explore as guest" })).not.toBeInTheDocument();
  });
});

describe("sandbox mode", () => {
  it("shows the banner and the Sandbox link", async () => {
    renderAs("VIEWER", "/", SANDBOX_ON);
    expect(await screen.findByRole("note")).toHaveTextContent("simulated AWS account");
    const nav = within(screen.getByRole("navigation", { name: "Main" }));
    expect(nav.getByRole("link", { name: "Sandbox" })).toHaveAttribute("href", "/sandbox");
  });

  it("hides both in normal mode", async () => {
    renderAs("VIEWER", "/");
    await screen.findByRole("heading", { name: "Dashboard" });
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Sandbox" })).not.toBeInTheDocument();
  });

  it("lists the switches and lets an analyst flip one", async () => {
    const { fetchMock } = renderAs("ANALYST", "/sandbox", {
      ...SANDBOX_ON,
      "GET /api/sandbox": { status: 200, body: sandboxState() },
      "PATCH /api/sandbox/controls/rdp-open": { status: 200, body: control("rdp-open", true) },
    });
    const rdp = (await screen.findByText("Remote Desktop open to the internet")).closest("li");
    expect(rdp).not.toBeNull();
    const row = within(rdp as HTMLElement);
    expect(row.getByText("Secure")).toBeInTheDocument();
    expect(row.getByRole("link", { name: "CS-SG-002" })).toHaveAttribute(
      "href",
      "/findings?rule_id=CS-SG-002",
    );

    fireEvent.click(row.getByRole("button", { name: "Make insecure" }));
    expect(await row.findByText("Insecure")).toBeInTheDocument();
    expect(row.getByRole("button", { name: "Fix it" })).toBeInTheDocument();
    const [, init] = fetchMock.mock.calls.find(
      ([input]) => String(input) === "/api/sandbox/controls/rdp-open",
    )!;
    expect(JSON.parse(String(init?.body))).toEqual({ insecure: true });
  });

  it("resets every switch", async () => {
    const { fetchMock } = renderAs("ANALYST", "/sandbox", {
      ...SANDBOX_ON,
      "GET /api/sandbox": { status: 200, body: sandboxState(false, true) },
      "POST /api/sandbox/reset": { status: 200, body: sandboxState(true, false) },
    });
    await screen.findByText("SSH open to the internet");
    expect(screen.getAllByText("Insecure")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Reset to defaults" }));
    const ssh = (await screen.findByText("SSH open to the internet")).closest("li") as HTMLElement;
    expect(await within(ssh).findByText("Insecure")).toBeInTheDocument();
    expect(callsTo(fetchMock, "POST /api/sandbox/reset")).toBe(1);
  });

  it("shows a clear message when changes are rate limited", async () => {
    renderAs("ANALYST", "/sandbox", {
      ...SANDBOX_ON,
      "GET /api/sandbox": { status: 200, body: sandboxState() },
      "PATCH /api/sandbox/controls/ssh-open": { status: 429 },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Fix it" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Too many changes");
  });

  it("gives viewers a read-only view", async () => {
    renderAs("VIEWER", "/sandbox", {
      ...SANDBOX_ON,
      "GET /api/sandbox": { status: 200, body: sandboxState() },
    });
    await screen.findByText("SSH open to the internet");
    expect(screen.queryByRole("button", { name: /Fix it|Make insecure|Reset/ })).not.toBeInTheDocument();
    expect(screen.getByText(/can look at the switches but not change them/)).toBeInTheDocument();
  });

  it("says so when sandbox mode is off", async () => {
    renderAs("ANALYST", "/sandbox", {
      "GET /api/about": {
        status: 200,
        body: { version: "0.1.0", sandbox_mode: false, guest_access: false },
      },
      "GET /api/sandbox": { status: 404 },
    });
    expect(await screen.findByText(/Sandbox mode is off/)).toBeInTheDocument();
  });
});

describe("slow server notice", () => {
  afterEach(() => setSlowRequestThreshold(3000));

  it("appears while a request is slow, for example a sleeping server starting up", async () => {
    setSlowRequestThreshold(50);
    renderLogin({ "GET /api/about": PENDING, "POST /api/auth/refresh": PENDING });
    expect(await screen.findByRole("status")).toHaveTextContent("starting up");
  });

  it("does not appear for quick answers", async () => {
    renderLogin({ ...SANDBOX_ON });
    await screen.findByRole("button", { name: "Explore as guest" });
    expect(screen.queryByText(/taking a while to answer/)).not.toBeInTheDocument();
  });
});
