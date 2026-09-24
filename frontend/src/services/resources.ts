import type { Page, ResourceDetail, ResourceSummary } from "../types/api";
import { apiGet, apiGetPage, toQuery } from "./api";

export interface ResourceQuery {
  aws_account_id?: string;
  resource_type?: string;
  region?: string;
  limit?: number;
  offset?: number;
}

export function listResources(query: ResourceQuery = {}): Promise<Page<ResourceSummary>> {
  return apiGetPage<ResourceSummary>(`/resources${toQuery({ ...query })}`);
}

export function getResource(id: string): Promise<ResourceDetail> {
  return apiGet<ResourceDetail>(`/resources/${encodeURIComponent(id)}`);
}
