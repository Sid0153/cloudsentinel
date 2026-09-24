import type { Page, Scan } from "../types/api";
import { apiGet, apiGetPage, apiRequest, toQuery } from "./api";

export const ACTIVE_SCAN_STATUSES = ["PENDING", "RUNNING"];

export function listScans(query: { aws_account_id?: string; limit?: number; offset?: number } = {}): Promise<Page<Scan>> {
  return apiGetPage<Scan>(`/scans${toQuery(query)}`);
}

export function getScan(id: string): Promise<Scan> {
  return apiGet<Scan>(`/scans/${encodeURIComponent(id)}`);
}

export function startScan(awsAccountId: string): Promise<Scan> {
  return apiRequest<Scan>("/scans", { method: "POST", body: { aws_account_id: awsAccountId } });
}
