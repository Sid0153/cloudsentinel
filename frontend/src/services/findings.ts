import type {
  Category,
  FindingDetail,
  FindingStatus,
  FindingSummary,
  Page,
  Severity,
} from "../types/api";
import { apiGet, apiGetPage, apiRequest, toQuery } from "./api";

export type FindingSort = "risk" | "severity" | "last_detected" | "first_detected" | "rule_id" | "resource_id";

export interface FindingQuery {
  q?: string;
  severity?: Severity[];
  status?: FindingStatus[];
  category?: Category | "";
  resource_type?: string;
  resource_uuid?: string;
  rule_id?: string;
  aws_account_id?: string;
  sort?: FindingSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export function listFindings(query: FindingQuery = {}): Promise<Page<FindingSummary>> {
  return apiGetPage<FindingSummary>(`/findings${toQuery({ ...query })}`);
}

export function getFinding(id: string): Promise<FindingDetail> {
  return apiGet<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
}

export function updateFindingStatus(
  id: string,
  status: FindingStatus,
  note: string,
): Promise<FindingDetail> {
  return apiRequest<FindingDetail>(`/findings/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: { status, note: note.trim() || null },
  });
}
