// Mirrors the backend's HealthResponse schema.
export interface HealthStatus {
  status: "ok" | "unavailable";
  database?: "up" | "down" | null;
}
