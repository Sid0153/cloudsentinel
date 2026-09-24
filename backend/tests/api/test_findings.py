"""Findings end to end: moto AWS -> scan -> rule engine -> PostgreSQL -> findings API.

Covers de-duplication across scans, automatic closing (only when a scan proves the problem is
gone), reopening, analyst triage and the list filters.
"""

import uuid
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.aws.collectors import iam as iam_collector
from app.domain.resources import NormalizedResource, ResourceType
from app.models.aws_account import AwsAccount
from app.models.finding import Finding, FindingStatus
from app.models.scan import ScanStatus
from app.models.user import User
from app.rules.model import Outcome, Rule, RuleContext, check
from app.services.rule_catalog import get_rule_catalog
from tests.api.conftest import RunScan
from tests.aws.seed import Seeded
from tests.helpers import bearer

ALICE = "arn:aws:iam::123456789012:user/alice"
OPS_ADMIN = "arn:aws:iam::123456789012:role/ops-admin"

def _findings(db_session: Session) -> dict[tuple[str, str], Finding]:
    return {(f.rule_id, f.resource_id): f for f in db_session.scalars(select(Finding))}


def _get(client: TestClient, user: User, **params: Any) -> list[dict[str, Any]]:
    response = client.get("/api/findings", headers=bearer(user), params=params)
    assert response.status_code == 200, response.text
    result: list[dict[str, Any]] = response.json()
    return result


# --- Detection -----------------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_scan_turns_the_seeded_misconfigurations_into_findings(
    db_client: TestClient, run_scan: RunScan, viewer: User, seeded: Seeded
) -> None:
    scan = run_scan()
    assert scan.status == ScanStatus.COMPLETED
    assert scan.finding_count == 7
    assert scan.finding_counts == {"HIGH": 5, "MEDIUM": 2}
    statuses = {rule_id: r["status"] for rule_id, r in scan.rule_results.items()}
    assert statuses == {
        "CS-CT-001": "PASSED",  # the seeded trail is multi-region and logging
        "CS-IAM-001": "FAILED",
        "CS-IAM-002": "FAILED",
        "CS-S3-001": "FAILED",
        "CS-S3-002": "FAILED",
        "CS-SG-001": "FAILED",
        "CS-SG-002": "PASSED",
        "CS-SG-003": "PASSED",
    }

    found = {(f["rule_id"], f["resource_id"], f["severity"]) for f in _get(db_client, viewer)}
    assert found == {
        ("CS-SG-001", seeded.open_group_id, "HIGH"),
        ("CS-S3-001", "cs-public-bucket", "HIGH"),
        # moto does not apply AWS's default SSE-S3 encryption; real accounts rarely fail this.
        ("CS-S3-002", "cs-public-bucket", "MEDIUM"),
        ("CS-S3-002", "cs-audit-logs", "MEDIUM"),
        ("CS-IAM-001", ALICE, "HIGH"),  # console password, no MFA, and "*" permissions
        ("CS-IAM-002", ALICE, "HIGH"),
        ("CS-IAM-002", OPS_ADMIN, "HIGH"),
    }


@pytest.mark.usefixtures("seeded")
def test_finding_detail_has_evidence_rule_text_and_resource(
    db_client: TestClient, run_scan: RunScan, viewer: User, seeded: Seeded
) -> None:
    run_scan()
    summary = _get(db_client, viewer, rule_id="CS-SG-001")[0]
    assert "evidence" not in summary  # the list is a summary

    detail = db_client.get(f"/api/findings/{summary['id']}", headers=bearer(viewer)).json()
    assert detail["status"] == "OPEN"
    assert detail["resource_name"] == "ssh-open"
    assert detail["evidence"]["open_rules"] == [
        {"protocol": "tcp", "ports": "22", "sources": ["0.0.0.0/0"]}
    ]
    assert seeded.instance_id in detail["evidence"]["attached_instance_ids"]
    assert detail["rule"]["id"] == "CS-SG-001"
    assert "Session Manager" in detail["rule"]["remediation"]
    assert detail["rule"]["references"][0]["url"].startswith("https://docs.aws.amazon.com/")

    resource = db_client.get(f"/api/resources/{detail['resource_uuid']}", headers=bearer(viewer))
    assert resource.json()["resource_id"] == seeded.open_group_id


# --- Re-scans --------------------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_rescan_updates_findings_instead_of_duplicating_them(
    db_session: Session, run_scan: RunScan
) -> None:
    first = run_scan()
    before = {key: (f.id, f.first_detected) for key, f in _findings(db_session).items()}
    second = run_scan()
    after = _findings(db_session)

    assert db_session.scalar(select(func.count()).select_from(Finding)) == 7
    assert {key: (f.id, f.first_detected) for key, f in after.items()} == before
    for finding in after.values():
        assert finding.first_scan_id == first.id
        assert finding.last_scan_id == second.id
        assert finding.last_detected >= finding.first_detected


@pytest.mark.usefixtures("seeded")
def test_fixing_the_problem_in_aws_resolves_the_finding_and_breaking_it_reopens_it(
    db_session: Session, run_scan: RunScan, seeded: Seeded
) -> None:
    run_scan()
    ssh_permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.revoke_security_group_ingress(
        GroupId=seeded.open_group_id, IpPermissions=[ssh_permission]
    )

    fixed_scan = run_scan()
    finding = _findings(db_session)[("CS-SG-001", seeded.open_group_id)]
    assert finding.status == FindingStatus.RESOLVED
    assert finding.status_note == "A later scan found this fixed"
    assert finding.status_updated_by_id is None  # closed by the scan, not a person
    assert finding.resolved_at is not None
    assert finding.last_scan_id != fixed_scan.id  # it was not detected by that scan
    assert fixed_scan.finding_count == 6

    ec2.authorize_security_group_ingress(
        GroupId=seeded.open_group_id, IpPermissions=[ssh_permission]
    )
    run_scan()
    finding = _findings(db_session)[("CS-SG-001", seeded.open_group_id)]
    assert finding.status == FindingStatus.OPEN
    assert finding.status_note == "Detected again by a later scan"
    assert finding.resolved_at is None


@pytest.mark.usefixtures("seeded")
def test_deleted_resource_resolves_its_findings(db_session: Session, run_scan: RunScan) -> None:
    run_scan()
    iam = boto3.client("iam", region_name="us-east-1")
    policy_arn = "arn:aws:iam::123456789012:policy/ops-full-access"
    iam.detach_role_policy(RoleName="ops-admin", PolicyArn=policy_arn)
    iam.delete_role(RoleName="ops-admin")

    run_scan()
    finding = _findings(db_session)[("CS-IAM-002", OPS_ADMIN)]
    assert finding.status == FindingStatus.RESOLVED
    assert finding.status_note == "The resource was no longer found by a complete scan"


@pytest.mark.usefixtures("seeded")
def test_access_denied_never_closes_a_finding(
    db_session: Session, run_scan: RunScan, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_scan()

    def denied(iam: object) -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetAccountAuthorizationDetails",
        )

    monkeypatch.setattr(iam_collector, "read_authorization_details", denied)
    scan = run_scan()

    assert scan.status == ScanStatus.COMPLETED_WITH_ERRORS
    iam_rule = scan.rule_results["CS-IAM-002"]
    assert iam_rule["status"] == "INCOMPLETE"  # not PASSED, although nothing was detected
    assert iam_rule["unknown"] == 2  # both users: their policies could not be read
    findings = _findings(db_session)
    # alice is present but UNKNOWN; the role is missing because IAM was only partly read.
    assert findings[("CS-IAM-002", ALICE)].status == FindingStatus.OPEN
    assert findings[("CS-IAM-002", OPS_ADMIN)].status == FindingStatus.OPEN
    # MFA data comes from the credential report, which still worked.
    assert findings[("CS-IAM-001", ALICE)].last_scan_id == scan.id


@pytest.mark.usefixtures("seeded")
def test_a_crashing_rule_marks_the_scan_and_keeps_the_other_findings(
    db_session: Session, run_scan: RunScan
) -> None:
    @check("CS-BUG-001", ResourceType.S3_BUCKET)
    def broken(resource: NormalizedResource, context: RuleContext) -> Outcome:
        raise ValueError("bug in a rule")

    template = get_rule_catalog().rules[0]
    broken_rule = Rule(metadata=template.metadata, check=broken)
    scan = run_scan(rules=[*get_rule_catalog().rules, broken_rule])

    assert scan.status == ScanStatus.COMPLETED_WITH_ERRORS
    assert scan.finding_count == 7
    assert "bug in a rule" not in str(scan.rule_results)


# --- Triage ---------------------------------------------------------------------------------


def _patch(client: TestClient, user: User, finding_id: uuid.UUID, **body: Any) -> Any:
    return client.patch(f"/api/findings/{finding_id}", headers=bearer(user), json=body)


@pytest.mark.usefixtures("seeded")
def test_analyst_decisions_survive_later_scans(
    db_client: TestClient, db_session: Session, run_scan: RunScan, analyst: User
) -> None:
    run_scan()
    findings = _findings(db_session)
    acknowledged = findings[("CS-IAM-001", ALICE)]
    false_positive = findings[("CS-IAM-002", OPS_ADMIN)]
    claimed_fixed = findings[("CS-S3-002", "cs-audit-logs")]

    response = _patch(db_client, analyst, acknowledged.id, status="ACKNOWLEDGED", note=" soon ")
    assert response.status_code == 200
    assert response.json()["status_note"] == "soon"
    assert response.json()["status_updated_by_id"] == str(analyst.id)
    reason = "Break-glass role, access is monitored"
    assert _patch(
        db_client, analyst, false_positive.id, status="FALSE_POSITIVE", note=reason
    ).status_code == 200
    assert _patch(db_client, analyst, claimed_fixed.id, status="RESOLVED").status_code == 200

    run_scan()
    findings = _findings(db_session)
    assert findings[("CS-IAM-001", ALICE)].status == FindingStatus.ACKNOWLEDGED
    assert findings[("CS-IAM-002", OPS_ADMIN)].status == FindingStatus.FALSE_POSITIVE
    assert findings[("CS-IAM-002", OPS_ADMIN)].status_note == reason
    # Marked resolved, but the scan still sees the problem: reopened.
    assert findings[("CS-S3-002", "cs-audit-logs")].status == FindingStatus.OPEN


@pytest.mark.usefixtures("seeded")
def test_status_update_validation_and_permissions(
    db_client: TestClient, db_session: Session, run_scan: RunScan, analyst: User, viewer: User
) -> None:
    run_scan()
    finding = _findings(db_session)[("CS-S3-001", "cs-public-bucket")]

    no_reason = _patch(db_client, analyst, finding.id, status="FALSE_POSITIVE", note="   ")
    assert no_reason.status_code == 422
    assert _patch(db_client, analyst, finding.id, status="CLOSED").status_code == 422
    too_long = _patch(db_client, analyst, finding.id, status="ACKNOWLEDGED", note="x" * 501)
    assert too_long.status_code == 422
    assert _patch(db_client, viewer, finding.id, status="RESOLVED").status_code == 403
    assert _patch(db_client, analyst, uuid.uuid4(), status="RESOLVED").status_code == 404
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN


# --- Listing ---------------------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_list_filters_search_and_sorting(
    db_client: TestClient, run_scan: RunScan, viewer: User, account: AwsAccount
) -> None:
    run_scan()

    def rules(**params: Any) -> list[str]:
        return [f["rule_id"] for f in _get(db_client, viewer, **params)]

    assert rules(severity="MEDIUM") == ["CS-S3-002", "CS-S3-002"]
    assert len(rules(severity=["HIGH", "CRITICAL"])) == 5
    assert rules(category="LOGGING") == []
    assert set(rules(resource_type="AWS::IAM::Role")) == {"CS-IAM-002"}
    assert len(rules(status="OPEN", aws_account_id=str(account.id))) == 7
    assert rules(status="RESOLVED") == []
    assert len(rules(aws_account_id=str(uuid.uuid4()))) == 0
    assert set(rules(q="ALICE")) == {"CS-IAM-001", "CS-IAM-002"}  # case-insensitive
    assert rules(q="%") == []  # LIKE wildcards in user input are literal characters
    assert rules(region="global", rule_id="CS-IAM-001") == ["CS-IAM-001"]

    by_severity = _get(db_client, viewer)
    assert [f["severity"] for f in by_severity] == ["HIGH"] * 5 + ["MEDIUM"] * 2
    assert rules(sort="rule_id", order="asc")[0] == "CS-IAM-001"
    assert len(rules(limit=2, offset=6)) == 1


@pytest.mark.parametrize(
    "params",
    [
        {"severity": "SEVERE"},
        {"status": "DONE"},
        {"sort": "title; DROP TABLE findings"},
        {"order": "sideways"},
        {"limit": 1000},
        {"q": "x" * 201},
        {"resource_type": "AWS::Nope"},
    ],
)
def test_invalid_list_parameters_are_rejected(
    db_client: TestClient, viewer: User, params: dict[str, Any]
) -> None:
    response = db_client.get("/api/findings", headers=bearer(viewer), params=params)
    assert response.status_code == 422


def test_unknown_finding_returns_404(db_client: TestClient, viewer: User) -> None:
    response = db_client.get(f"/api/findings/{uuid.uuid4()}", headers=bearer(viewer))
    assert response.status_code == 404


def test_rules_endpoint_lists_the_catalog(db_client: TestClient, viewer: User) -> None:
    rules = db_client.get("/api/rules", headers=bearer(viewer)).json()
    assert len(rules) == 8
    ssh = next(r for r in rules if r["id"] == "CS-SG-001")
    assert ssh["severity"] == "HIGH"
    assert ssh["resource_types"] == ["AWS::EC2::SecurityGroup"]
    assert ssh["remediation"] and ssh["limitations"]


# --- Risk (Phase 6) --------------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_findings_are_scored_and_listed_highest_risk_first(
    db_client: TestClient, run_scan: RunScan, viewer: User
) -> None:
    scan = run_scan()
    assert scan.risk_summary == {
        "model_version": 1,
        "max_score": 85,
        "by_priority": {"P1": 4, "P2": 1, "P3": 0, "P4": 2},
    }
    listed = [(f["rule_id"], f["risk_score"]) for f in _get(db_client, viewer)]
    assert [score for _, score in listed] == [85, 85, 85, 80, 75, 35, 35]
    assert listed[3:5] == [("CS-IAM-002", 80), ("CS-IAM-002", 75)]  # user with a password, role

    assert [f["risk_score"] for f in _get(db_client, viewer, min_risk=80)] == [85, 85, 85, 80]
    ascending = _get(db_client, viewer, sort="risk", order="asc")
    assert ascending[0]["risk_score"] == 35
    response = db_client.get("/api/findings", headers=bearer(viewer), params={"min_risk": 101})
    assert response.status_code == 422


@pytest.mark.usefixtures("seeded")
def test_finding_detail_explains_the_score(
    db_client: TestClient, run_scan: RunScan, viewer: User
) -> None:
    run_scan()
    summary = _get(db_client, viewer, rule_id="CS-SG-001")[0]
    detail = db_client.get(f"/api/findings/{summary['id']}", headers=bearer(viewer)).json()
    breakdown = detail["risk_breakdown"]
    assert detail["risk_score"] == breakdown["score"] == 85
    assert breakdown["priority"] == "P1"
    assert breakdown["severity"] == {"level": "HIGH", "points": 40}
    assert breakdown["exposure"]["level"] == "INTERNET"
    assert "public IP" in breakdown["exposure"]["reason"]
    assert breakdown["impact"]["points"] == 20
    assert breakdown["confidence"]["points"] == 0


@pytest.mark.usefixtures("seeded")
def test_risk_follows_the_current_exposure(
    db_session: Session, run_scan: RunScan, seeded: Seeded
) -> None:
    run_scan()
    finding = _findings(db_session)[("CS-SG-001", seeded.open_group_id)]
    assert finding.risk_score == 85

    boto3.client("ec2", region_name="us-east-1").stop_instances(InstanceIds=[seeded.instance_id])
    run_scan()
    finding = _findings(db_session)[("CS-SG-001", seeded.open_group_id)]
    # Still open to the internet, but no running instance with a public IP uses the group.
    assert finding.risk_breakdown is not None
    assert finding.risk_breakdown["exposure"]["level"] == "INDIRECT"
    assert finding.risk_score == 70


@pytest.mark.usefixtures("seeded")
def test_false_positives_are_left_out_of_the_scan_risk_summary(
    db_client: TestClient, db_session: Session, run_scan: RunScan, analyst: User
) -> None:
    run_scan()
    role_finding = _findings(db_session)[("CS-IAM-002", OPS_ADMIN)]
    response = _patch(
        db_client, analyst, role_finding.id, status="FALSE_POSITIVE", note="Break-glass role"
    )
    assert response.status_code == 200

    scan = run_scan()
    assert scan.risk_summary["by_priority"] == {"P1": 4, "P2": 0, "P3": 0, "P4": 2}
    assert scan.finding_count == 7  # still detected and counted, just not in the risk summary
