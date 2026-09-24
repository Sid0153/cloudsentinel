"""CS-S3-001 (public bucket) and CS-S3-002 (no default encryption)."""

from typing import Any

import pytest

from app.domain.resources import PublicAccessBlock, S3BucketConfig
from app.rules.checks.s3 import block_setting_in_force, encryption_disabled, public_bucket
from app.rules.model import Outcome, OutcomeStatus, Severity, config_of
from tests.fixtures.resources import ALL_BLOCKED, NOTHING_BLOCKED, bucket, context

ONLY_IGNORE_ACLS = PublicAccessBlock(False, True, False, False)
ONLY_RESTRICT = PublicAccessBlock(False, False, False, True)


def _public(**config: Any) -> Outcome:
    resource = bucket(**config)
    return public_bucket.evaluate(resource, context(resource))


# --- Block Public Access: bucket level OR account level ----------------------------------


def _config(**overrides: Any) -> S3BucketConfig:
    return config_of(bucket(**overrides), S3BucketConfig)


def test_block_setting_from_either_level_applies() -> None:
    assert block_setting_in_force(_config(), "ignore_public_acls") is False
    for level in ("public_access_block", "account_public_access_block"):
        assert block_setting_in_force(_config(**{level: ALL_BLOCKED}), "ignore_public_acls")


def test_unreadable_block_is_unknown_unless_the_other_level_blocks() -> None:
    unknown = _config(unknown_checks=["account_public_access_block"])
    assert block_setting_in_force(unknown, "restrict_public_buckets") is None
    covered = _config(
        unknown_checks=["account_public_access_block"], public_access_block=ALL_BLOCKED
    )
    assert block_setting_in_force(covered, "restrict_public_buckets") is True


# --- CS-S3-001 ---------------------------------------------------------------------------


def test_private_bucket_passes() -> None:
    assert _public().status == OutcomeStatus.PASS
    assert _public(public_access_block=ALL_BLOCKED).status == OutcomeStatus.PASS


@pytest.mark.parametrize(
    ("grants", "severity"),
    [
        (["AllUsers:READ"], Severity.HIGH),
        (["AuthenticatedUsers:READ_ACP"], Severity.HIGH),
        (["AllUsers:WRITE"], Severity.CRITICAL),
        (["AllUsers:READ", "AuthenticatedUsers:FULL_CONTROL"], Severity.CRITICAL),
        (["AllUsers:WRITE_ACP"], Severity.CRITICAL),
    ],
)
def test_public_acl_fails_with_severity_by_permission(
    grants: list[str], severity: Severity
) -> None:
    outcome = _public(acl_public_grants=grants, public_access_block=NOTHING_BLOCKED)
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == severity
    assert outcome.evidence["public_acl_grants"] == grants
    assert outcome.evidence["public_write"] is (severity == Severity.CRITICAL)


def test_public_policy_is_high() -> None:
    outcome = _public(policy_is_public=True)
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == Severity.HIGH
    assert outcome.evidence["public_policy"] is True
    assert "public_acl_grants" not in outcome.evidence


@pytest.mark.parametrize("level", ["public_access_block", "account_public_access_block"])
def test_block_public_access_neutralizes_public_acl_and_policy(level: str) -> None:
    assert _public(acl_public_grants=["AllUsers:WRITE"], **{level: ONLY_IGNORE_ACLS}).status == (
        OutcomeStatus.PASS
    )
    assert _public(policy_is_public=True, **{level: ONLY_RESTRICT}).status == OutcomeStatus.PASS


def test_the_wrong_block_setting_does_not_neutralize() -> None:
    # IgnorePublicAcls does not affect a public policy, and RestrictPublicBuckets not an ACL.
    assert _public(policy_is_public=True, public_access_block=ONLY_IGNORE_ACLS).status == (
        OutcomeStatus.FAIL
    )
    assert _public(
        acl_public_grants=["AllUsers:READ"], public_access_block=ONLY_RESTRICT
    ).status == OutcomeStatus.FAIL


@pytest.mark.parametrize(
    "config",
    [
        {"unknown_checks": ["acl"]},
        {"policy_is_public": None, "unknown_checks": ["policy_status"]},
        {  # public grant, but whether the account ignores public ACLs is unknown
            "acl_public_grants": ["AllUsers:READ"],
            "unknown_checks": ["account_public_access_block"],
        },
        {  # public policy, but the bucket-level block could not be read
            "policy_is_public": True,
            "unknown_checks": ["public_access_block"],
        },
    ],
)
def test_missing_data_is_unknown_never_a_pass(config: dict[str, Any]) -> None:
    outcome = _public(**config)
    assert outcome.status == OutcomeStatus.UNKNOWN
    assert outcome.reason


def test_confirmed_public_evidence_wins_over_another_unknown_check() -> None:
    outcome = _public(acl_public_grants=["AllUsers:READ"], unknown_checks=["policy_status"])
    assert outcome.status == OutcomeStatus.FAIL


# --- CS-S3-002 ---------------------------------------------------------------------------


def _encryption(**config: Any) -> Outcome:
    resource = bucket(**config)
    return encryption_disabled.evaluate(resource, context(resource))


def test_encrypted_bucket_passes() -> None:
    assert _encryption().status == OutcomeStatus.PASS
    assert _encryption(encryption_algorithm="aws:kms").status == OutcomeStatus.PASS


def test_bucket_without_default_encryption_fails() -> None:
    outcome = _encryption(encryption_configured=False, encryption_algorithm=None)
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity is None  # rule default: MEDIUM
    assert outcome.evidence == {"default_encryption": None}


def test_unreadable_encryption_is_unknown() -> None:
    outcome = _encryption(encryption_configured=None, unknown_checks=["encryption"])
    assert outcome.status == OutcomeStatus.UNKNOWN
