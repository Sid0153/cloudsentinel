from app.aws.normalizers.iam import find_broad_statements, normalize_iam
from app.aws.raw import RawIam
from app.domain.resources import IamRoleConfig, IamUserConfig, NormalizedResource
from tests.fixtures.aws_raw import (
    ADMIN_ARN,
    AUTHORIZATION_DETAILS,
    CREDENTIAL_REPORT,
    LOCAL_POLICY_ARN,
)


def _by_name(resources: list[NormalizedResource]) -> dict[str | None, NormalizedResource]:
    return {r.name: r for r in resources}


def _user(resources: list[NormalizedResource], name: str) -> IamUserConfig:
    config = _by_name(resources)[name].config
    assert isinstance(config, IamUserConfig)
    return config


def test_root_account_row_is_not_stored() -> None:
    resources = normalize_iam(
        RawIam(credential_report=CREDENTIAL_REPORT, authorization_details=AUTHORIZATION_DETAILS)
    )
    assert all("root" not in r.resource_id for r in resources)
    assert {r.name for r in resources} == {"alice", "ci-bot", "deployer"}


def test_user_with_console_password_and_no_mfa() -> None:
    resources = normalize_iam(
        RawIam(credential_report=CREDENTIAL_REPORT, authorization_details=AUTHORIZATION_DETAILS)
    )
    alice = _user(resources, "alice")
    assert alice.password_enabled is True
    assert alice.mfa_active is False
    assert alice.access_key_1_active is True
    assert alice.permissions_analyzed is True


def test_admin_access_through_a_group_and_inline_star_policy() -> None:
    resources = normalize_iam(
        RawIam(credential_report=CREDENTIAL_REPORT, authorization_details=AUTHORIZATION_DETAILS)
    )
    alice = _user(resources, "alice")
    assert alice.uses_admin_managed_policy is True
    assert alice.groups == ["admins"]
    assert [s.source for s in alice.broad_statements] == ["inline:star"]
    assert alice.broad_statements[0].actions == ["*"]


def test_only_the_default_version_of_a_managed_policy_is_analyzed() -> None:
    resources = normalize_iam(
        RawIam(credential_report=CREDENTIAL_REPORT, authorization_details=AUTHORIZATION_DETAILS)
    )
    bot = _user(resources, "ci-bot")
    assert bot.attached_policy_arns == [LOCAL_POLICY_ARN]
    # The URL-encoded inline policy is scoped, so only the managed "s3:*" statement is broad.
    assert [(s.source, s.actions) for s in bot.broad_statements] == [
        (f"managed:{LOCAL_POLICY_ARN}", ["s3:*"])
    ]
    assert bot.uses_admin_managed_policy is False
    assert bot.access_key_2_active is None  # "N/A" in the report


def test_role_service_wildcard_with_condition_is_flagged_and_deny_is_ignored() -> None:
    resources = normalize_iam(RawIam(authorization_details=AUTHORIZATION_DETAILS))
    role = _by_name(resources)["deployer"].config
    assert isinstance(role, IamRoleConfig)
    assert len(role.broad_statements) == 1
    statement = role.broad_statements[0]
    assert statement.actions == ["ec2:*"]
    assert statement.has_condition is True
    assert "AssumeRolePolicyDocument" not in str(_by_name(resources)["deployer"].config_dict())


def test_without_policy_data_users_come_from_the_report_and_are_marked_unanalyzed() -> None:
    resources = normalize_iam(RawIam(credential_report=CREDENTIAL_REPORT))
    alice = _user(resources, "alice")
    assert alice.permissions_analyzed is False
    assert alice.broad_statements == []
    assert alice.mfa_active is False


def test_without_the_report_mfa_status_is_unknown() -> None:
    resources = normalize_iam(RawIam(authorization_details=AUTHORIZATION_DETAILS))
    alice = _user(resources, "alice")
    assert alice.mfa_active is None
    assert alice.password_enabled is None


def test_nothing_readable_gives_no_resources() -> None:
    assert normalize_iam(RawIam()) == []


def test_broad_statement_detection_edge_cases() -> None:
    assert find_broad_statements({"Statement": []}, "x") == []
    assert find_broad_statements("not json", "x") == []
    assert find_broad_statements(None, "x") == []
    # Wildcard action but a specific resource is not "broad" under this rule.
    scoped = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"}]}
    assert find_broad_statements(scoped, "x") == []
    # NotAction is deliberately not analyzed.
    not_action = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    assert find_broad_statements(not_action, "x") == []
    assert ADMIN_ARN.endswith("AdministratorAccess")
