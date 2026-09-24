"""CS-IAM-001 (console user without MFA) and CS-IAM-002 (overly broad permissions)."""

from typing import Any

import pytest

from app.domain.resources import NormalizedResource
from app.rules.checks.iam import console_user_without_mfa, overly_broad_permissions
from app.rules.model import Outcome, OutcomeStatus, Severity
from tests.fixtures.resources import broad, context, iam_role, iam_user


def _mfa(**config: Any) -> Outcome:
    user = iam_user(**config)
    return console_user_without_mfa.evaluate(user, context(user))


def _broad(resource: NormalizedResource) -> Outcome:
    return overly_broad_permissions.evaluate(resource, context(resource))


# --- CS-IAM-001 --------------------------------------------------------------------------


def test_console_user_with_mfa_passes() -> None:
    assert _mfa().status == OutcomeStatus.PASS


def test_user_without_console_password_is_not_affected() -> None:
    assert _mfa(password_enabled=False, mfa_active=False).status == OutcomeStatus.PASS


def test_console_user_without_mfa_is_medium() -> None:
    outcome = _mfa(mfa_active=False)
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == Severity.MEDIUM
    assert outcome.evidence == {"console_password": True, "mfa_active": False, "privileged": False}


@pytest.mark.parametrize(
    "privilege",
    [{"uses_admin_managed_policy": True}, {"broad_statements": [broad(["s3:*"])]}],
)
def test_privileged_console_user_without_mfa_is_high(privilege: dict[str, Any]) -> None:
    outcome = _mfa(mfa_active=False, **privilege)
    assert outcome.severity == Severity.HIGH
    assert outcome.evidence["privileged"] is True


def test_unknown_permissions_keep_medium_and_say_so() -> None:
    outcome = _mfa(mfa_active=False, permissions_analyzed=False)
    assert outcome.severity == Severity.MEDIUM
    assert outcome.evidence["privileged"] is None


@pytest.mark.parametrize(
    "config",
    [
        {"password_enabled": None, "mfa_active": None},  # no credential report
        {"password_enabled": True, "mfa_active": None},
    ],
)
def test_missing_credential_report_data_is_unknown(config: dict[str, Any]) -> None:
    assert _mfa(**config).status == OutcomeStatus.UNKNOWN


# --- CS-IAM-002 --------------------------------------------------------------------------


def test_identities_without_broad_permissions_pass() -> None:
    assert _broad(iam_user()).status == OutcomeStatus.PASS
    assert _broad(iam_role()).status == OutcomeStatus.PASS


@pytest.mark.parametrize(
    ("config", "severity", "full_admin"),
    [
        ({"uses_admin_managed_policy": True}, Severity.HIGH, True),
        ({"broad_statements": [broad(["*"])]}, Severity.HIGH, True),
        ({"broad_statements": [broad(["s3:*", "ec2:*"])]}, Severity.MEDIUM, False),
        ({"broad_statements": [broad(["*"], condition=True)]}, Severity.MEDIUM, False),
        (
            {"broad_statements": [broad(["s3:*"]), broad(["*"])]},
            Severity.HIGH,
            True,
        ),
    ],
)
@pytest.mark.parametrize("kind", ["user", "role"])
def test_broad_permissions_fail_with_severity_by_scope(
    config: dict[str, Any], severity: Severity, full_admin: bool, kind: str
) -> None:
    resource = iam_user(**config) if kind == "user" else iam_role(**config)
    outcome = _broad(resource)
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == severity
    assert outcome.evidence["full_admin"] is full_admin


def test_evidence_lists_where_each_statement_comes_from() -> None:
    statement = broad(["*"])
    outcome = _broad(iam_user(broad_statements=[statement]))
    assert outcome.evidence["broad_statements"] == [
        {"source": "inline:test", "actions": ["*"], "resources": ["*"], "has_condition": False}
    ]


def test_evidence_is_capped_but_the_count_is_kept() -> None:
    outcome = _broad(iam_role(broad_statements=[broad(["s3:*"])] * 25))
    assert outcome.evidence["broad_statement_count"] == 25
    assert len(outcome.evidence["broad_statements"]) == 20


def test_user_whose_policies_could_not_be_read_is_unknown() -> None:
    assert _broad(iam_user(permissions_analyzed=False)).status == OutcomeStatus.UNKNOWN


def test_service_linked_roles_are_skipped() -> None:
    role = iam_role(path="/aws-service-role/", uses_admin_managed_policy=True)
    assert _broad(role).status == OutcomeStatus.PASS
