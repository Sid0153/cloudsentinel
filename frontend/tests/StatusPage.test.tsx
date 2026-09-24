import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import StatusPage from "../src/pages/StatusPage";
import { mockFetchRoutes } from "./mockApi";

describe("StatusPage", () => {
  it("shows a loading state while the request is pending", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    render(<StatusPage />);
    expect(screen.getByRole("status")).toHaveTextContent("Checking API status");
  });

  it("shows API and database as healthy on success", async () => {
    const fetchMock = mockFetchRoutes({
      "GET /api/health/ready": { status: 200, body: { status: "ok", database: "up" } },
    });
    render(<StatusPage />);
    expect(await screen.findByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Online")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/health/ready", expect.anything());
  });

  it("shows the database as unreachable when the API reports 503", async () => {
    mockFetchRoutes({
      "GET /api/health/ready": { status: 503, body: { status: "unavailable", database: "down" } },
    });
    render(<StatusPage />);
    expect(await screen.findByText("Unreachable")).toBeInTheDocument();
  });

  it("shows an error when the API cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network down")));
    render(<StatusPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach");
  });

  it("shows an error for unexpected server failures", async () => {
    mockFetchRoutes({ "GET /api/health/ready": { status: 500, body: { detail: "boom" } } });
    render(<StatusPage />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
