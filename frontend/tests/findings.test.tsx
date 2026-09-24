import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FINDING_DETAIL, finding } from "./fixtures";
import { requestedUrls } from "./mockApi";
import { renderAs } from "./renderApp";

const LIST = {
  "GET /api/findings": {
    status: 200,
    body: [finding(), finding({ id: "ffffffff-0000-0000-0000-000000000002", severity: "MEDIUM", risk_score: 35, title: "S3 bucket has no default encryption configured", resource_id: "arn:aws:s3:::logs/bucket" })],
    headers: { "X-Total-Count": "30" },
  },
};
const DETAIL_URL = `/api/findings/${FINDING_DETAIL.id}`;

describe("Findings list", () => {
  it("lists findings with risk, severity and a link to the detail", async () => {
    renderAs("VIEWER", "/findings", LIST);
    const link = await screen.findByRole("link", { name: "Security group allows SSH from the internet" });
    expect(link).toHaveAttribute("href", `/findings/${FINDING_DETAIL.id}`);
    expect(screen.getByText("85 · P1")).toBeInTheDocument();
    expect(screen.getByText("35 · P4")).toBeInTheDocument();
    expect(screen.getByText("1–25 of 30")).toBeInTheDocument(); // total from X-Total-Count
  });

  it("asks for open findings by risk by default, and filters by severity", async () => {
    const { fetchMock } = renderAs("VIEWER", "/findings", LIST);
    await screen.findByText("85 · P1");
    expect(requestedUrls(fetchMock, "GET", "/api/findings")[0]).toBe(
      "/api/findings?status=OPEN&status=ACKNOWLEDGED&sort=risk&order=desc&limit=25&offset=0",
    );

    fireEvent.click(screen.getByRole("checkbox", { name: "High" }));
    await waitFor(() =>
      expect(requestedUrls(fetchMock, "GET", "/api/findings").at(-1)).toContain("severity=HIGH"),
    );
  });

  it("searches when the form is submitted", async () => {
    const { fetchMock } = renderAs("VIEWER", "/findings", LIST);
    await screen.findByText("85 · P1");
    fireEvent.change(screen.getByLabelText("Search findings"), { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() =>
      expect(requestedUrls(fetchMock, "GET", "/api/findings").at(-1)).toContain("q=alice"),
    );
  });

  it("pages through results", async () => {
    const { fetchMock } = renderAs("VIEWER", "/findings", LIST);
    await screen.findByText("1–25 of 30");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(requestedUrls(fetchMock, "GET", "/api/findings").at(-1)).toContain("offset=25"),
    );
  });

  it("shows an empty state", async () => {
    renderAs("VIEWER", "/findings", { "GET /api/findings": { status: 200, body: [], headers: { "X-Total-Count": "0" } } });
    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
  });

  it("shows an error state", async () => {
    renderAs("VIEWER", "/findings", { "GET /api/findings": { status: 500 } });
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load data");
  });
});

describe("Finding detail", () => {
  it("shows evidence, risk explanation, remediation and safe references", async () => {
    renderAs("VIEWER", `/findings/${FINDING_DETAIL.id}`, {
      [`GET ${DETAIL_URL}`]: { status: 200, body: FINDING_DETAIL },
    });
    expect(await screen.findByRole("heading", { name: FINDING_DETAIL.title })).toBeInTheDocument();
    expect(screen.getByText(/"sources": \[/)).toBeInTheDocument(); // evidence rendered as JSON text
    expect(screen.getByText("Attached to 1 running instance(s) with a public IP address")).toBeInTheDocument();
    expect(screen.getByText("+25")).toBeInTheDocument();
    expect(screen.getByText(/Remove the rule/)).toBeInTheDocument();
    expect(screen.getByText(/constantly scanned/)).toBeInTheDocument();

    const docs = screen.getByRole("link", { name: "Security group rules" });
    expect(docs).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.queryByRole("link", { name: "Not https" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "sg-0123" })).toHaveAttribute("href", `/resources/${FINDING_DETAIL.resource_uuid}`);
  });

  it("does not offer triage to viewers", async () => {
    renderAs("VIEWER", `/findings/${FINDING_DETAIL.id}`, {
      [`GET ${DETAIL_URL}`]: { status: 200, body: FINDING_DETAIL },
    });
    await screen.findByRole("heading", { name: FINDING_DETAIL.title });
    expect(screen.queryByRole("button", { name: "Save status" })).not.toBeInTheDocument();
  });

  it("lets an analyst change the status", async () => {
    const { fetchMock } = renderAs("ANALYST", `/findings/${FINDING_DETAIL.id}`, {
      [`GET ${DETAIL_URL}`]: { status: 200, body: FINDING_DETAIL },
      [`PATCH ${DETAIL_URL}`]: {
        status: 200,
        body: { ...FINDING_DETAIL, status: "ACKNOWLEDGED", status_note: "Ticket 42", status_updated_by_id: "u1" },
      },
    });
    await screen.findByRole("heading", { name: FINDING_DETAIL.title });
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "ACKNOWLEDGED" } });
    fireEvent.change(screen.getByLabelText(/Note/), { target: { value: "Ticket 42" } });
    fireEvent.click(screen.getByRole("button", { name: "Save status" }));

    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    const patch = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
    expect(JSON.parse(String(patch?.[1]?.body))).toEqual({ status: "ACKNOWLEDGED", note: "Ticket 42" });
    const header = screen.getByRole("heading", { name: FINDING_DETAIL.title }).parentElement as HTMLElement;
    expect(within(header).getByText("Acknowledged")).toBeInTheDocument();
  });

  it("requires a note for a false positive before calling the API", async () => {
    const { fetchMock } = renderAs("ANALYST", `/findings/${FINDING_DETAIL.id}`, {
      [`GET ${DETAIL_URL}`]: { status: 200, body: FINDING_DETAIL },
    });
    await screen.findByRole("heading", { name: FINDING_DETAIL.title });
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "FALSE_POSITIVE" } });
    fireEvent.click(screen.getByRole("button", { name: "Save status" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Explain why");
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "PATCH")).toBe(false);
  });

  it("shows not found for an unknown finding", async () => {
    renderAs("VIEWER", `/findings/${FINDING_DETAIL.id}`, { [`GET ${DETAIL_URL}`]: { status: 404 } });
    expect(await screen.findByRole("alert")).toHaveTextContent("Not found");
  });
});
