const API_BASE = "/api";

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export interface SendOptions {
  method?: string;
  body?: unknown;
  token?: string | null;
}

// Requests that take longer than this show a "the server is starting" notice. A backend on a
// free hosting plan is stopped after a while without visitors; the next request then waits
// for it to start, which can take up to a minute.
let slowAfterMs = 3000;
let pending = 0;
let slow = false;
const slowListeners = new Set<() => void>();

function setSlow(value: boolean): void {
  if (slow === value) return;
  slow = value;
  slowListeners.forEach((listener) => listener());
}

export function subscribeToSlowRequests(listener: () => void): () => void {
  slowListeners.add(listener);
  return () => slowListeners.delete(listener);
}

export function requestsAreSlow(): boolean {
  return slow;
}

/** For tests: how long a request may take before it counts as slow. */
export function setSlowRequestThreshold(ms: number): void {
  slowAfterMs = ms;
}

/** For tests: forget requests a test left unanswered on purpose. */
export function resetSlowRequests(): void {
  pending = 0;
  setSlow(false);
}

export function send(path: string, options: SendOptions = {}): Promise<Response> {
  pending += 1;
  const timer = setTimeout(() => setSlow(true), slowAfterMs);
  return sendNow(path, options).finally(() => {
    clearTimeout(timer);
    pending -= 1;
    if (pending === 0) setSlow(false);
  });
}

function sendNow(path: string, options: SendOptions): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }
  return fetch(`${API_BASE}${path}`, {
    method: options.method ?? "GET",
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
}

export async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new ApiError(`Request failed with status ${response.status}`, response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}
