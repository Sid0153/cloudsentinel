import { vi } from "vitest";

export interface MockReply {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

// Keys look like "POST /api/auth/login". A value may be a function to vary replies per call.
// A key without a query string also matches the same path with any query string; an exact
// key (with its query string) wins.
// PENDING: the request never answers, to test loading states.
export const PENDING = "PENDING";
export type MockRoutes = Record<string, MockReply | (() => MockReply) | typeof PENDING>;

export function mockFetchRoutes(routes: MockRoutes) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const method = (init?.method ?? "GET").toUpperCase();
    const key = `${method} ${String(input)}`;
    const route = routes[key] ?? routes[key.split("?")[0]];
    if (route === undefined) {
      throw new Error(`Unexpected request: ${key}`);
    }
    if (route === PENDING) {
      return new Promise<Response>(() => {});
    }
    const reply = typeof route === "function" ? route() : route;
    return {
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      headers: new Headers(reply.headers ?? {}),
      json: async () => reply.body,
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

/** The URLs (with query strings) requested for a method and path. */
export function requestedUrls(
  fetchMock: ReturnType<typeof mockFetchRoutes>,
  method: string,
  path: string,
): string[] {
  return fetchMock.mock.calls
    .filter(([, init]) => (init?.method ?? "GET").toUpperCase() === method)
    .map(([input]) => String(input))
    .filter((url) => url.split("?")[0] === path);
}

export function callsTo(fetchMock: ReturnType<typeof mockFetchRoutes>, key: string): number {
  return fetchMock.mock.calls.filter(([input, init]) => {
    const method = (init?.method ?? "GET").toUpperCase();
    return `${method} ${String(input)}` === key;
  }).length;
}

export function tokenReply(role: "ADMIN" | "ANALYST" | "VIEWER", email: string): MockReply {
  return {
    status: 200,
    body: {
      access_token: "access-token-1",
      expires_in: 900,
      user: {
        id: "11111111-1111-1111-1111-111111111111",
        email,
        role,
        is_active: true,
        created_at: "2026-01-01T00:00:00Z",
        last_login_at: null,
      },
    },
  };
}
