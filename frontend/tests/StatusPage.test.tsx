import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "../src/App";

function mockFetchOnce(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderApp(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("StatusPage", () => {
  it("shows a loading state while the request is pending", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderApp();
    expect(screen.getByRole("status")).toHaveTextContent("Checking API status");
  });

  it("shows API and database as healthy on success", async () => {
    const fetchMock = mockFetchOnce(200, { status: "ok", database: "up" });
    renderApp();
    expect(await screen.findByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Online")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/health/ready", expect.anything());
  });

  it("shows the database as unreachable when the API reports 503", async () => {
    mockFetchOnce(503, { status: "unavailable", database: "down" });
    renderApp();
    expect(await screen.findByText("Unreachable")).toBeInTheDocument();
  });

  it("shows an error when the API cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network down")));
    renderApp();
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach");
  });

  it("shows an error for unexpected server failures", async () => {
    mockFetchOnce(500, { detail: "Internal server error" });
    renderApp();
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});

describe("routing", () => {
  it("renders the not-found page for unknown routes", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderApp("/does-not-exist");
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});
