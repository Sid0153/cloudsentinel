import { refreshSession } from "./auth";
import { ApiError, readJson, send, type SendOptions } from "./http";
import { tokenStore } from "./tokenStore";

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
export async function apiRequest<T>(path: string, options: SendOptions = {}): Promise<T> {
  const hadToken = tokenStore.get() !== null;
  let response = await send(path, { ...options, token: tokenStore.get() });

  if (response.status === 401 && hadToken) {
    try {
      await refreshSession();
    } catch {
      sessionExpiredListener?.();
      throw new ApiError("Session expired", 401);
    }
    response = await send(path, { ...options, token: tokenStore.get() });
  }
  return readJson<T>(response);
}

export function apiGet<T>(path: string): Promise<T> {
  return apiRequest<T>(path);
}
