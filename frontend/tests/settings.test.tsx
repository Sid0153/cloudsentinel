import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ACCOUNT, RULE } from "./fixtures";
import { callsTo } from "./mockApi";
import { renderAs } from "./renderApp";

const BASE = {
  "GET /api/aws-accounts": { status: 200, body: [ACCOUNT] },
  "GET /api/rules": { status: 200, body: [RULE] },
};

describe("Settings", () => {
  it("shows accounts, rules and system status to every role, without admin forms for viewers", async () => {
    renderAs("VIEWER", "/settings", BASE);
    expect(await screen.findByText("Production")).toBeInTheDocument();
    expect(await screen.findByText(RULE.title)).toBeInTheDocument();
    expect(await screen.findByText("Connected")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register account" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verify access" })).not.toBeInTheDocument();
  });

  it("lets an admin register an AWS account", async () => {
    const { fetchMock } = renderAs("ADMIN", "/settings", {
      ...BASE,
      "POST /api/aws-accounts": { status: 201, body: ACCOUNT },
    });
    fireEvent.change(await screen.findByLabelText("Account ID"), { target: { value: "210987654321" } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Staging" } });
    fireEvent.change(screen.getByLabelText("Regions (comma-separated)"), { target: { value: "us-east-1, eu-west-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Register account" }));

    await waitFor(() => expect(callsTo(fetchMock, "POST /api/aws-accounts")).toBe(1));
    const [, init] =
      fetchMock.mock.calls.find(([input, options]) => String(input) === "/api/aws-accounts" && options?.method === "POST") ?? [];
    expect(JSON.parse(String(init?.body))).toEqual({ account_id: "210987654321", name: "Staging", regions: ["us-east-1", "eu-west-1"], role_arn: null });
  });

  it("shows the verification result", async () => {
    renderAs("ADMIN", "/settings", {
      ...BASE,
      [`POST /api/aws-accounts/${ACCOUNT.id}/verify`]: {
        status: 200,
        body: { expected_account_id: "123456789012", caller_account_id: "999999999999", caller_arn: "arn", matches: false },
      },
    });
    fireEvent.click(await screen.findByRole("button", { name: "Verify access" }));
    expect(await screen.findByText("Mismatch: credentials belong to 999999999999")).toBeInTheDocument();
  });

  it("signs out after a password change, and reports a wrong current password", async () => {
    let replies = 0;
    const { fetchMock } = renderAs("VIEWER", "/settings", {
      ...BASE,
      "POST /api/auth/change-password": () => (replies++ === 0 ? { status: 400 } : { status: 204 }),
      "POST /api/auth/logout": { status: 204 },
    });
    fireEvent.change(await screen.findByLabelText("Current password"), { target: { value: "wrong-password-1" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "a-new-password-123" } });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("The current password is incorrect.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(callsTo(fetchMock, "POST /api/auth/logout")).toBe(1);
  });
});
