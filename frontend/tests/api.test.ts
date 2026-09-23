import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiGet } from "../src/services/api";
import { getReadiness } from "../src/services/health";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiGet", () => {
  it("throws ApiError with the status for non-2xx responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({}) }));
    await expect(apiGet("/anything")).rejects.toMatchObject({ name: "ApiError", status: 401 });
    await expect(apiGet("/anything")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("getReadiness", () => {
  it("does not throw on 503", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503, json: async () => ({}) }));
    await expect(getReadiness()).resolves.toEqual({ status: "unavailable", database: "down" });
  });

  it("rethrows other errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500, json: async () => ({}) }));
    await expect(getReadiness()).rejects.toBeInstanceOf(ApiError);
  });
});
