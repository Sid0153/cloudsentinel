import type { DashboardSummary } from "../types/api";
import { apiGet, toQuery } from "./api";

export function getDashboard(awsAccountId?: string): Promise<DashboardSummary> {
  return apiGet<DashboardSummary>(`/dashboard/summary${toQuery({ aws_account_id: awsAccountId })}`);
}
