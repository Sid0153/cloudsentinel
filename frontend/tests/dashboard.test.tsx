import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ACCOUNT, dashboard } from "./fixtures";
import { PENDING, requestedUrls } from "./mockApi";
import { renderAs } from "./renderApp";

describe("Dashboard", () => {
  it("shows the headline numbers, charts and top risks from the API", async () => {
    renderAs("VIEWER", "/");
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();

    expect(await screen.findByText("Open findings")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getAllByText("85 · P1")).toHaveLength(2); // overall risk tile + top risks row
    expect(screen.getByRole("link", { name: "Highest open finding" })).toHaveAttribute(
      "href",
      "/findings/ffffffff-0000-0000-0000-000000000001",
    );

    const bySeverity = screen.getByRole("list", { name: "Open findings by severity" });
    const high = within(bySeverity).getByTitle("High: 5 open findings");
    expect(high).toHaveTextContent("5");
    expect(within(bySeverity).getAllByRole("listitem")).toHaveLength(4);

    const topRisk = screen.getByRole("link", { name: "S3 bucket is publicly accessible" });
    expect(topRisk).toHaveAttribute("href", "/findings/ffffffff-0000-0000-0000-000000000002");
  });

  it("shows a loading state", async () => {
    renderAs("VIEWER", "/", { "GET /api/dashboard/summary": PENDING });
    expect(await screen.findByText("Loading dashboard…")).toBeInTheDocument();
  });

  it("explains what to do before the first scan", async () => {
    renderAs("VIEWER", "/", {
      "GET /api/dashboard/summary": {
        status: 200,
        body: dashboard({ latest_scan: null, top_risks: [], overall_risk: null, open_finding_count: 0 }),
      },
    });
    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to Scans" })).toHaveAttribute("href", "/scans");
  });

  it("shows an error with a retry button", async () => {
    renderAs("VIEWER", "/", { "GET /api/dashboard/summary": { status: 500 } });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Could not load data");
    expect(within(alert).getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("can narrow the dashboard to one AWS account", async () => {
    const other = { ...ACCOUNT, id: "aaaaaaaa-0000-0000-0000-000000000002", name: "Staging" };
    const { fetchMock } = renderAs("VIEWER", `/?account=${other.id}`, {
      "GET /api/aws-accounts": { status: 200, body: [ACCOUNT, other] },
    });
    expect(await screen.findByRole("combobox")).toHaveValue(other.id);
    expect(requestedUrls(fetchMock, "GET", "/api/dashboard/summary")).toContain(
      `/api/dashboard/summary?aws_account_id=${other.id}`,
    );
  });
});
