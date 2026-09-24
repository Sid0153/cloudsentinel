import { refreshSession } from "./auth";
import { ApiError, readJson, send, type SendOptions } from "./http";
import { tokenStore } from "./tokenStore";
import type { Page } from "../types/api";

export { ApiError };

let sessionExpiredListener: (() => void) | null = null;

/** The AuthProvider registers here so a failed refresh sends the user back to the login page. */
export function onSessionExpired(listener: (() => void) | null): void {
  sessionExpiredListener = listener;
}

/**
 * Calls the API with the in-memory access token. If the server answers 401 for a signed-in
 * user, the token has probably expired: refresh once and retry once.
 */
async function apiFetch(path: string, options: SendOptions = {}): Promise<Response> {
  const hadToken = tokenStore.get() !== null;
  const response = await send(path, { ...options, token: tokenStore.get() });

  if (response.status === 401 && hadToken) {
    try {
      await refreshSession();
    } catch {
      sessionExpiredListener?.();
      throw new ApiError("Session expired", 401);
    }
    return send(path, { ...options, token: tokenStore.get() });
  }
  return response;
}

export async function apiRequest<T>(path: string, options: SendOptions = {}): Promise<T> {
  return readJson<T>(await apiFetch(path, options));
}

export function apiGet<T>(path: string): Promise<T> {
  return apiRequest<T>(path);
}

/** One page of a list endpoint, with the total from the X-Total-Count header. */
export async function apiGetPage<T>(path: string): Promise<Page<T>> {
  const response = await apiFetch(path);
  const items = await readJson<T[]>(response);
  const header = response.headers?.get("X-Total-Count");
  const total = header === null || header === undefined ? items.length : Number(header);
  return { items, total: Number.isFinite(total) ? total : items.length };
}

type QueryValue = string | number | undefined | null | readonly string[];

/** Builds "?a=1&b=x&b=y", skipping empty values. Repeated keys express "any of". */
export function toQuery(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, item);
    } else {
      search.append(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}
