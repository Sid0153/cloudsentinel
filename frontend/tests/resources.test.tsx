import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RESOURCE, finding } from "./fixtures";
import { requestedUrls } from "./mockApi";
import { renderAs } from "./renderApp";

describe("Resources", () => {
  it("lists resources and filters by type", async () => {
    const { fetchMock } = renderAs("VIEWER", "/resources", {
      "GET /api/resources": { status: 200, body: [RESOURCE], headers: { "X-Total-Count": "1" } },
    });
    expect(await screen.findByRole("link", { name: "ssh-open" })).toHaveAttribute("href", `/resources/${RESOURCE.id}`);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "AWS::S3::Bucket" } });
    await waitFor(() =>
      expect(requestedUrls(fetchMock, "GET", "/api/resources").at(-1)).toContain(
        "resource_type=AWS%3A%3AS3%3A%3ABucket",
      ),
    );
  });

  it("shows an empty state before any scan", async () => {
    renderAs("VIEWER", "/resources", {
      "GET /api/resources": { status: 200, body: [], headers: { "X-Total-Count": "0" } },
    });
    expect(await screen.findByText(/Run a scan to discover resources/)).toBeInTheDocument();
  });

  it("shows a resource with its configuration and findings", async () => {
    renderAs("VIEWER", `/resources/${RESOURCE.id}`, {
      [`GET /api/resources/${RESOURCE.id}`]: { status: 200, body: RESOURCE },
      "GET /api/findings": { status: 200, body: [finding()], headers: { "X-Total-Count": "1" } },
    });
    expect(await screen.findByRole("heading", { name: "ssh-open" })).toBeInTheDocument();
    expect(screen.getByText(/"group_name": "ssh-open"/)).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: finding().title })).toBeInTheDocument();
  });
});
