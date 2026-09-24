"""The engine: dispatch by resource type, per-rule summaries, errors and determinism."""

import pytest

from app.domain.coverage import CoverageStatus
from app.domain.resources import NormalizedResource, ResourceType, resource_key
from app.rules.engine import RuleResultStatus, evaluate
from app.rules.model import (
    Category,
    CheckFunction,
    Outcome,
    Rule,
    RuleContext,
    RuleMetadata,
    Severity,
    check,
)
from app.services.rule_catalog import get_rule_catalog
from tests.fixtures.resources import (
    account,
    bucket,
    full_coverage,
    iam_user,
    inbound,
    security_group,
    trail,
)


def _rule(rule_id: str, function: CheckFunction, *types: ResourceType) -> Rule:
    metadata = RuleMetadata(
        id=rule_id,
        title="Test rule",
        category=Category.NETWORK,
        severity=Severity.LOW,
        description="d",
        rationale="r",
        remediation="f",
    )
    return Rule(metadata=metadata, check=check(rule_id, *types)(function))


def _fails_every_bucket(resource: NormalizedResource, context: RuleContext) -> Outcome:
    return Outcome.failed({"bucket": resource.resource_id})


def _unknown(resource: NormalizedResource, context: RuleContext) -> Outcome:
    return Outcome.unknown("could not read it")


def _passes(resource: NormalizedResource, context: RuleContext) -> Outcome:
    return Outcome.passed()


def _crashes(resource: NormalizedResource, context: RuleContext) -> Outcome:
    raise KeyError("bug")


def test_rules_only_see_their_resource_types() -> None:
    rule = _rule("CS-T-001", _fails_every_bucket, ResourceType.S3_BUCKET)
    evaluation = evaluate([rule], [bucket("a"), bucket("b"), iam_user()], full_coverage())
    assert [d.resource.resource_id for d in evaluation.detections] == ["a", "b"]
    assert all(d.severity == Severity.LOW for d in evaluation.detections)  # the rule default
    assert evaluation.rule_results["CS-T-001"]["evaluated"] == 2


def test_summary_statuses() -> None:
    rules = [
        _rule("CS-T-001", _fails_every_bucket, ResourceType.S3_BUCKET),
        _rule("CS-T-002", _passes, ResourceType.S3_BUCKET),
        _rule("CS-T-003", _unknown, ResourceType.S3_BUCKET),
        _rule("CS-T-004", _passes, ResourceType.IAM_ROLE),  # no roles exist
    ]
    results = evaluate(rules, [bucket()], full_coverage()).rule_results
    assert results["CS-T-001"]["status"] == RuleResultStatus.FAILED
    assert results["CS-T-002"]["status"] == RuleResultStatus.PASSED
    assert results["CS-T-003"]["status"] == RuleResultStatus.INCOMPLETE
    assert results["CS-T-003"]["unknown_samples"] == [
        {"resource_id": "bucket", "reason": "could not read it"}
    ]
    assert results["CS-T-004"]["status"] == RuleResultStatus.NOT_APPLICABLE


@pytest.mark.parametrize("status", [CoverageStatus.PARTIAL, CoverageStatus.FAILED])
def test_incomplete_coverage_is_never_reported_as_passed(status: str) -> None:
    coverage = full_coverage()
    coverage["s3"]["status"] = status
    rule = _rule("CS-T-001", _passes, ResourceType.S3_BUCKET)
    # Every bucket that was read passes, and even zero buckets is not "not applicable".
    for resources in ([bucket()], []):
        result = evaluate([rule], resources, coverage).rule_results["CS-T-001"]
        assert result["status"] == RuleResultStatus.INCOMPLETE
        assert result["coverage_complete"] is False


def test_a_crashing_rule_is_an_error_and_does_not_stop_the_others() -> None:
    rules = [
        _rule("CS-T-001", _crashes, ResourceType.S3_BUCKET),
        _rule("CS-T-002", _fails_every_bucket, ResourceType.S3_BUCKET),
    ]
    evaluation = evaluate(rules, [bucket()], full_coverage())
    assert evaluation.had_errors
    result = evaluation.rule_results["CS-T-001"]
    assert result["status"] == RuleResultStatus.ERROR
    assert "bug" not in str(result)  # exception details stay in the server log
    assert len(evaluation.detections) == 1


def test_passed_pairs_are_recorded_for_closing_findings() -> None:
    rule = _rule("CS-T-002", _passes, ResourceType.S3_BUCKET)
    resource = bucket()
    evaluation = evaluate([rule], [resource], full_coverage())
    assert evaluation.passed == {("CS-T-002", resource_key(resource))}


def test_real_catalog_on_a_mixed_environment() -> None:
    resources = [
        account(),
        trail(),
        security_group(inbound("tcp", 22, v4=["0.0.0.0/0"]), group_id="sg-open"),
        security_group(group_id="sg-closed"),
        bucket("public", acl_public_grants=["AllUsers:READ"]),
        bucket("private"),
        iam_user("alice", mfa_active=False, uses_admin_managed_policy=True),
    ]
    rules = get_rule_catalog().rules
    first = evaluate(rules, resources, full_coverage())
    found = sorted((d.rule.id, d.resource.resource_id, str(d.severity)) for d in first.detections)
    assert found == [
        ("CS-IAM-001", "arn:aws:iam::123456789012:user/alice", "HIGH"),
        ("CS-IAM-002", "arn:aws:iam::123456789012:user/alice", "HIGH"),
        ("CS-S3-001", "public", "HIGH"),
        ("CS-SG-001", "sg-open", "HIGH"),
    ]
    assert first.rule_results["CS-CT-001"]["status"] == RuleResultStatus.PASSED
    assert first.rule_results["CS-SG-002"]["status"] == RuleResultStatus.PASSED

    # Deterministic: the same input gives exactly the same result.
    second = evaluate(rules, resources, full_coverage())
    assert [(d.rule.id, d.evidence) for d in first.detections] == [
        (d.rule.id, d.evidence) for d in second.detections
    ]
    assert first.rule_results == second.rule_results
