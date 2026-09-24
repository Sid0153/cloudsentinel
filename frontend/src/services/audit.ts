import type { AuditLogEntry, Page } from "../types/api";
import { apiGetPage, toQuery } from "./api";

// Mirrors AuditAction in backend/app/audit/events.py.
export const AUDIT_ACTIONS = [
  "LOGIN_SUCCEEDED",
  "LOGIN_FAILED",
  "LOGIN_RATE_LIMITED",
  "ACCOUNT_LOCKED",
  "LOGOUT",
  "PASSWORD_CHANGED",
  "REFRESH_TOKEN_REUSED",
  "ACCESS_DENIED",
  "USER_CREATED",
  "USER_UPDATED",
  "AWS_ACCOUNT_REGISTERED",
  "AWS_ACCOUNT_VERIFIED",
  "SCAN_STARTED",
  "SCAN_COMPLETED",
  "SCAN_FAILED",
  "FINDING_STATUS_CHANGED",
] as const;

export interface AuditQuery {
  action?: string;
  outcome?: string;
  limit?: number;
  offset?: number;
}

export function listAuditLogs(query: AuditQuery = {}): Promise<Page<AuditLogEntry>> {
  return apiGetPage<AuditLogEntry>(`/audit-logs${toQuery({ ...query })}`);
}
