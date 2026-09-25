// Mirrors the backend schemas in backend/app/schemas/. Dates are ISO 8601 strings.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Category = "NETWORK" | "DATA_PROTECTION" | "IDENTITY" | "LOGGING";
export type FindingStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "FALSE_POSITIVE";
export type Priority = "P1" | "P2" | "P3" | "P4";
export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "COMPLETED_WITH_ERRORS" | "FAILED";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const CATEGORIES: Category[] = ["NETWORK", "DATA_PROTECTION", "IDENTITY", "LOGGING"];
export const FINDING_STATUSES: FindingStatus[] = ["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"];
export const RESOURCE_TYPES = [
  "AWS::Account",
  "AWS::EC2::Instance",
  "AWS::EC2::SecurityGroup",
  "AWS::S3::Bucket",
  "AWS::IAM::User",
  "AWS::IAM::Role",
  "AWS::CloudTrail::Trail",
] as const;

export interface Page<T> {
  items: T[];
  total: number;
}

export interface AwsAccount {
  id: string;
  account_id: string;
  name: string;
  regions: string[];
  role_arn: string | null;
  created_at: string;
}

export interface AwsAccountVerification {
  expected_account_id: string;
  caller_account_id: string;
  caller_arn: string;
  matches: boolean;
}

export interface CoverageEntry {
  status: "SUCCEEDED" | "PARTIAL" | "FAILED";
  items: number;
  error_count: number;
  errors: string[];
}

export interface RuleResult {
  status: "PASSED" | "FAILED" | "INCOMPLETE" | "NOT_APPLICABLE" | "ERROR";
  evaluated: number;
  passed: number;
  failed: number;
  unknown: number;
  coverage_complete: boolean;
  unknown_samples: { resource_id: string; reason: string }[];
}

export interface RiskSummary {
  model_version?: number;
  max_score?: number | null;
  by_priority?: Record<Priority, number>;
}

export interface Scan {
  id: string;
  aws_account_id: string;
  status: ScanStatus;
  triggered_by_id: string | null;
  caller_arn: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  resource_count: number;
  resource_counts: Record<string, number>;
  coverage: Record<string, CoverageEntry>;
  error_summary: string | null;
  finding_count: number;
  finding_counts: Partial<Record<Severity, number>>;
  risk_summary: RiskSummary;
  rule_results: Record<string, RuleResult>;
}

export interface ResourceSummary {
  id: string;
  aws_account_id: string;
  region: string;
  resource_type: string;
  resource_id: string;
  name: string | null;
  first_seen: string;
  last_seen: string;
  last_scan_id: string | null;
}

export interface ResourceDetail extends ResourceSummary {
  config: Record<string, unknown>;
}

export interface Rule {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  resource_types: string[];
  description: string;
  rationale: string;
  remediation: string;
  severity_note: string | null;
  limitations: string | null;
  references: { title: string; url: string }[];
}

export interface FindingSummary {
  id: string;
  aws_account_id: string;
  resource_uuid: string;
  rule_id: string;
  title: string;
  category: Category;
  severity: Severity;
  risk_score: number | null;
  status: FindingStatus;
  resource_type: string;
  resource_id: string;
  region: string;
  first_detected: string;
  last_detected: string;
  last_scan_id: string | null;
}

export interface RiskFactor {
  level: string;
  points: number;
  reason?: string;
}

export interface RiskBreakdown {
  model_version: number;
  score: number;
  priority: Priority;
  severity: RiskFactor;
  exposure: RiskFactor;
  impact: RiskFactor;
  confidence: RiskFactor;
}

export interface FindingDetail extends FindingSummary {
  evidence: Record<string, unknown>;
  risk_breakdown: RiskBreakdown | null;
  status_note: string | null;
  status_updated_at: string | null;
  status_updated_by_id: string | null;
  resolved_at: string | null;
  first_scan_id: string | null;
  resource_name: string | null;
  rule: Rule | null;
}

export interface DashboardSummary {
  aws_account_count: number;
  resource_count: number;
  resources_by_type: Record<string, number>;
  open_finding_count: number;
  findings_by_severity: Record<Severity, number>;
  findings_by_category: Record<Category, number>;
  findings_by_priority: Record<Priority, number>;
  findings_by_status: Record<FindingStatus, number>;
  overall_risk: { score: number; priority: Priority; finding_id: string } | null;
  latest_scan: Scan | null;
  top_risks: FindingSummary[];
}

export interface AuditLogEntry {
  id: string;
  created_at: string;
  action: string;
  outcome: "SUCCESS" | "FAILURE";
  actor_id: string | null;
  actor_email: string | null;
  target_type: string | null;
  target_id: string | null;
  ip_address: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
}

// GET /api/about: public, read before sign-in.
export interface About {
  version: string;
  sandbox_mode: boolean; // scans run against a simulated AWS, not a real account
  guest_access: boolean; // "Explore as guest" is available
}

export interface SandboxControl {
  key: string;
  title: string;
  description: string;
  rule_id: string;
  insecure: boolean;
  insecure_by_default: boolean;
}

export interface SandboxState {
  account_id: string;
  region: string;
  controls: SandboxControl[];
}
