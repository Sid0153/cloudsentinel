import { describe, expect, it, vi } from "vitest";

import { ApiError, apiGet, onSessionExpired } from "../src/services/api";
import { refreshSession } from "../src/services/auth";
import { getReadiness } from "../src/services/health";
import { tokenStore } from "../src/services/tokenStore";
import { callsTo, mockFetchRoutes, tokenReply } from "./mockApi";

describe("apiGet", () => {
  it("throws ApiError with the status for non-2xx responses", async () => {
    mockFetchRoutes({ "GET /api/anything": { status: 404, body: {} } });
    await expect(apiGet("/anything")).rejects.toBeInstanceOf(ApiError);
    await expect(apiGet("/anything")).rejects.toMatchObject({ status: 404 });
  });

  it("sends the access token in the Authorization header", async () => {
    tokenStore.set("my-token");
    const fetchMock = mockFetchRoutes({ "GET /api/thing": { status: 200, body: { ok: true } } });
    await apiGet("/thing");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer my-token");
  });

  it("does not attempt a refresh when nobody is signed in", async () => {
    const fetchMock = mockFetchRoutes({ "GET /api/thing": { status: 401, body: {} } });
    await expect(apiGet("/thing")).rejects.toMatchObject({ status: 401 });
    expect(callsTo(fetchMock, "POST /api/auth/refresh")).toBe(0);
  });

  it("refreshes once and retries when a signed-in request gets 401", async () => {
    tokenStore.set("expired-token");
    let calls = 0;
    const fetchMock = mockFetchRoutes({
      "GET /api/thing": () => (calls++ === 0 ? { status: 401 } : { status: 200, body: { ok: 1 } }),
      "POST /api/auth/refresh": tokenReply("VIEWER", "v@example.com"),
    });
    await expect(apiGet("/thing")).resolves.toEqual({ ok: 1 });
    expect(callsTo(fetchMock, "POST /api/auth/refresh")).toBe(1);
    expect(tokenStore.get()).toBe("access-token-1");
  });

  it("reports an expired session when the refresh fails", async () => {
    tokenStore.set("expired-token");
    const expired = vi.fn();
    onSessionExpired(expired);
    mockFetchRoutes({
      "GET /api/thing": { status: 401 },
      "POST /api/auth/refresh": { status: 401 },
    });
    await expect(apiGet("/thing")).rejects.toMatchObject({ status: 401 });
    expect(expired).toHaveBeenCalledTimes(1);
    expect(tokenStore.get()).toBeNull();
    onSessionExpired(null);
  });
});

describe("refreshSession", () => {
  it("shares one request between simultaneous callers", async () => {
    const fetchMock = mockFetchRoutes({
      "POST /api/auth/refresh": tokenReply("VIEWER", "v@example.com"),
    });
    await Promise.all([refreshSession(), refreshSession()]);
    expect(callsTo(fetchMock, "POST /api/auth/refresh")).toBe(1);
  });
});

describe("getReadiness", () => {
  it("does not throw on 503", async () => {
    mockFetchRoutes({ "GET /api/health/ready": { status: 503, body: {} } });
    await expect(getReadiness()).resolves.toEqual({ status: "unavailable", database: "down" });
  });

  it("rethrows other errors", async () => {
    mockFetchRoutes({ "GET /api/health/ready": { status: 500, body: {} } });
    await expect(getReadiness()).rejects.toBeInstanceOf(ApiError);
  });
});
