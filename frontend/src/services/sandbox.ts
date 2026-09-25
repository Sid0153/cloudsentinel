import type { SandboxControl, SandboxState } from "../types/api";
import { apiGet, apiRequest } from "./api";

export function getSandbox(): Promise<SandboxState> {
  return apiGet<SandboxState>("/sandbox");
}

export function setSandboxControl(key: string, insecure: boolean): Promise<SandboxControl> {
  return apiRequest<SandboxControl>(`/sandbox/controls/${encodeURIComponent(key)}`, {
    method: "PATCH",
    body: { insecure },
  });
}

export function resetSandbox(): Promise<SandboxState> {
  return apiRequest<SandboxState>("/sandbox/reset", { method: "POST" });
}
