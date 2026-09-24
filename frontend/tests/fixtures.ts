// Sample API responses shaped like the backend's schemas (see src/types/api.ts).
import type {
  AwsAccount,
  DashboardSummary,
  FindingDetail,
  FindingSummary,
  ResourceDetail,
  Rule,
  Scan,
} from "../src/types/api";

export const ACCOUNT: AwsAccount = {
  id: "aaaaaaaa-0000-0000-0000-000000000001",
  account_id: "123456789012",
  name: "Production",
  regions: ["us-east-1", "eu-west-1"],
  role_arn: null,
  created_at: "2026-09-01T10:00:00Z",
};

export const RULE: Rule = {
  id: "CS-SG-001",
  title: "Security group allows SSH from the internet",
  category: "NETWORK",
  severity: "HIGH",
  resource_types: ["AWS::EC2::SecurityGroup"],
  description: "An inbound rule lets any address reach TCP port 22.",
  rationale: "SSH exposed to the whole internet is constantly scanned and brute-forced.",
  remediation: "1. Open the security group.\n2. Remove the rule.",
  severity_note: null,
  limitations: "Only 0.0.0.0/0 and ::/0 count as the internet.",
  references: [
    { title: "Security group rules", url: "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html" },
    { title: "Not https", url: "javascript:alert(1)" },
  ],
};

export function finding(overrides: Partial<FindingSummary> = {}): FindingSummary {
  return {
    id: "ffffffff-0000-0000-0000-000000000001",
    aws_account_id: ACCOUNT.id,
    resource_uuid: "rrrrrrrr-0000-0000-0000-000000000001",
    rule_id: "CS-SG-001",
    title: "Security group allows SSH from the internet",
    category: "NETWORK",
    severity: "HIGH",
    risk_score: 85,
    status: "OPEN",
    resource_type: "AWS::EC2::SecurityGroup",
    resource_id: "sg-0123",
    region: "us-east-1",
    first_detected: "2026-09-20T10:00:00Z",
    last_detected: "2026-09-24T10:00:00Z",
    last_scan_id: "ssssssss-0000-0000-0000-000000000001",
    ...overrides,
  };
}

export const FINDING_DETAIL: FindingDetail = {
  ...finding(),
  evidence: { port: 22, open_rules: [{ protocol: "tcp", ports: "22", sources: ["0.0.0.0/0"] }] },
  risk_breakdown: {
    model_version: 1,
    score: 85,
    priority: "P1",
    severity: { level: "HIGH", points: 40 },
    exposure: { level: "INTERNET", points: 25, reason: "Attached to 1 running instance(s) with a public IP address" },
    impact: { level: "HIGH", points: 20, reason: "Remote administration" },
    confidence: { level: "HIGH", points: 0, reason: "All inputs were available" },
  },
  status_note: null,
  status_updated_at: null,
  status_updated_by_id: null,
  resolved_at: null,
  first_scan_id: "ssssssss-0000-0000-0000-000000000001",
  resource_name: "ssh-open",
  rule: RULE,
};

export function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "ssssssss-0000-0000-0000-000000000001",
    aws_account_id: ACCOUNT.id,
    status: "COMPLETED",
    triggered_by_id: null,
    caller_arn: "arn:aws:iam::123456789012:user/scanner",
    created_at: "2026-09-24T10:00:00Z",
    started_at: "2026-09-24T10:00:01Z",
    finished_at: "2026-09-24T10:00:09Z",
    resource_count: 12,
    resource_counts: { "AWS::S3::Bucket": 3, "AWS::EC2::SecurityGroup": 9 },
    coverage: {
      ec2: { status: "SUCCEEDED", items: 10, error_count: 0, errors: [] },
      iam: { status: "PARTIAL", items: 2, error_count: 1, errors: ["AccessDenied (GetAccountAuthorizationDetails)"] },
    },
    error_summary: null,
    finding_count: 2,
    finding_counts: { HIGH: 1, MEDIUM: 1 },
    risk_summary: { model_version: 1, max_score: 85, by_priority: { P1: 1, P2: 0, P3: 0, P4: 1 } },
    rule_results: {
      "CS-SG-001": { status: "FAILED", evaluated: 9, passed: 8, failed: 1, unknown: 0, coverage_complete: true, unknown_samples: [] },
      "CS-IAM-002": { status: "INCOMPLETE", evaluated: 2, passed: 0, failed: 0, unknown: 2, coverage_complete: false, unknown_samples: [] },
    },
    ...overrides,
  };
}

export const RESOURCE: ResourceDetail = {
  id: "rrrrrrrr-0000-0000-0000-000000000001",
  aws_account_id: ACCOUNT.id,
  region: "us-east-1",
  resource_type: "AWS::EC2::SecurityGroup",
  resource_id: "sg-0123",
  name: "ssh-open",
  first_seen: "2026-09-20T10:00:00Z",
  last_seen: "2026-09-24T10:00:00Z",
  last_scan_id: "ssssssss-0000-0000-0000-000000000001",
  config: { group_name: "ssh-open", inbound: [] },
};

export function dashboard(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    aws_account_count: 1,
    resource_count: 12,
    resources_by_type: { "AWS::S3::Bucket": 3 },
    open_finding_count: 7,
    findings_by_severity: { CRITICAL: 0, HIGH: 5, MEDIUM: 2, LOW: 0 },
    findings_by_category: { NETWORK: 1, DATA_PROTECTION: 3, IDENTITY: 3, LOGGING: 0 },
    findings_by_priority: { P1: 4, P2: 1, P3: 0, P4: 2 },
    findings_by_status: { OPEN: 7, ACKNOWLEDGED: 0, RESOLVED: 0, FALSE_POSITIVE: 0 },
    overall_risk: { score: 85, priority: "P1", finding_id: finding().id },
    latest_scan: scan(),
    top_risks: [finding(), finding({ id: "ffffffff-0000-0000-0000-000000000002", title: "S3 bucket is publicly accessible", risk_score: 80, resource_id: "cs-public-bucket" })],
    ...overrides,
  };
}
