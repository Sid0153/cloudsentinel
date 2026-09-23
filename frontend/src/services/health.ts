import type { HealthStatus } from "../types/health";
import { ApiError, apiGet } from "./api";

/** 503 is a meaningful answer ("API is up, database is not"), so it is not treated as a failure. */
export async function getReadiness(): Promise<HealthStatus> {
  try {
    return await apiGet<HealthStatus>("/health/ready");
  } catch (error) {
    if (error instanceof ApiError && error.status === 503) {
      return { status: "unavailable", database: "down" };
    }
    throw error;
  }
}
