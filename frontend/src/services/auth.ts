import type { TokenResponse, User } from "../types/auth";
import { readJson, send } from "./http";
import { tokenStore } from "./tokenStore";

export async function login(email: string, password: string): Promise<User> {
  const response = await send("/auth/login", { method: "POST", body: { email, password } });
  const data = await readJson<TokenResponse>(response);
  tokenStore.set(data.access_token);
  return data.user;
}

async function requestRefresh(): Promise<User> {
  try {
    const data = await readJson<TokenResponse>(await send("/auth/refresh", { method: "POST" }));
    tokenStore.set(data.access_token);
    return data.user;
  } catch (error) {
    tokenStore.set(null);
    throw error;
  }
}

// The backend rotates the refresh token on every use and treats a replayed token as theft.
// Two refresh calls at once (React StrictMode, or two requests failing together) must
// therefore share a single request instead of racing.
let inFlightRefresh: Promise<User> | null = null;

export function refreshSession(): Promise<User> {
  if (inFlightRefresh === null) {
    inFlightRefresh = requestRefresh().finally(() => {
      inFlightRefresh = null;
    });
  }
  return inFlightRefresh;
}

export async function logout(): Promise<void> {
  try {
    await send("/auth/logout", { method: "POST" });
  } finally {
    tokenStore.set(null);
  }
}
