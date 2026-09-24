"""The risk engine: worked examples per rule, the score arithmetic, bands and determinism.

The worked examples here are the same ones documented in docs/risk-model.md.
"""

from typing import Any

import pytest

from app.risk.model import (
    CONFIDENCE_POINTS,
    EXPOSURE_POINTS,
    IMPACT_POINTS,
    RISK_MODEL_VERSION,
    SEVERITY_POINTS,
    Priority,
    priority_for,
)
from app.risk.profiles import PROFILES
from app.risk.scoring import assess, summarize
from app.rules.model import Severity
from app.services.rule_catalog import get_rule_catalog

SG = "AWS::EC2::SecurityGroup"
BUCKET = "AWS::S3::Bucket"
USER = "AWS::IAM::User"
ROLE = "AWS::IAM::Role"
ACCOUNT = "AWS::Account"

PUBLIC_INSTANCE = {
    "attached_instance_ids": ["i-1"],
    "internet_facing_instance_ids": ["i-1"],
    "attachments_known": True,
}
PRIVATE_INSTANCE = {
    "attached_instance_ids": ["i-1"],
    "internet_facing_instance_ids": [],
    "attachments_known": True,
}
UNATTACHED = {
    "attached_instance_ids": [],
    "internet_facing_instance_ids": [],
    "attachments_known": True,
}
ATTACHMENTS_UNKNOWN = {**UNATTACHED, "attachments_known": False}
NO_LOGGING = {"some_single_region_trail_logging": False}
SOME_LOGGING = {"some_single_region_trail_logging": True}
CRITICAL, HIGH, MEDIUM = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM


def _sg(ports: str, services: list[str]) -> dict[str, Any]:
    return {**PUBLIC_INSTANCE, "exposures": [{"ports": ports, "sensitive_services": services}]}


def _user(password: bool | None, keys: int | None) -> dict[str, Any]:
    return {"full_admin": True, "console_password": password, "active_access_keys": keys}


# (rule, resource type, severity, evidence, expected score, "EXPOSURE/IMPACT/CONFIDENCE")
WORKED_EXAMPLES: list[tuple[str, str, Severity, dict[str, Any], int, str]] = [
    ("CS-SG-001", SG, HIGH, PUBLIC_INSTANCE, 85, "INTERNET/HIGH/HIGH"),
    ("CS-SG-001", SG, HIGH, PRIVATE_INSTANCE, 70, "INDIRECT/HIGH/HIGH"),
    ("CS-SG-002", SG, HIGH, UNATTACHED, 60, "LATENT/HIGH/MEDIUM"),
    ("CS-SG-001", SG, HIGH, ATTACHMENTS_UNKNOWN, 80, "INTERNET/HIGH/MEDIUM"),
    ("CS-SG-003", SG, HIGH, _sg("all", ["MySQL"]), 90, "INTERNET/SEVERE/HIGH"),
    ("CS-SG-003", SG, HIGH, _sg("3306", ["MySQL"]), 85, "INTERNET/HIGH/HIGH"),
    ("CS-SG-003", SG, MEDIUM, _sg("8080", []), 60, "INTERNET/LIMITED/HIGH"),
    ("CS-S3-001", BUCKET, CRITICAL, {"public_write": True}, 100, "INTERNET/SEVERE/HIGH"),
    ("CS-S3-001", BUCKET, HIGH, {"public_write": False}, 85, "INTERNET/HIGH/HIGH"),
    ("CS-S3-002", BUCKET, MEDIUM, {"default_encryption": None}, 35, "NONE/LIMITED/HIGH"),
    ("CS-IAM-001", USER, HIGH, {"privileged": True}, 85, "CONSOLE_LOGIN/SEVERE/HIGH"),
    ("CS-IAM-001", USER, MEDIUM, {"privileged": False}, 60, "CONSOLE_LOGIN/MODERATE/HIGH"),
    ("CS-IAM-001", USER, MEDIUM, {"privileged": None}, 55, "CONSOLE_LOGIN/MODERATE/MEDIUM"),
    ("CS-IAM-002", USER, HIGH, _user(False, 1), 80, "CREDENTIALS/SEVERE/HIGH"),
    ("CS-IAM-002", USER, HIGH, _user(False, 0), 70, "LATENT/SEVERE/HIGH"),
    ("CS-IAM-002", USER, HIGH, _user(None, None), 75, "CREDENTIALS/SEVERE/MEDIUM"),
    ("CS-IAM-002", ROLE, HIGH, {"full_admin": True}, 75, "INDIRECT/SEVERE/HIGH"),
    ("CS-IAM-002", ROLE, MEDIUM, {"full_admin": False}, 55, "INDIRECT/HIGH/HIGH"),
    (
        "CS-IAM-002",
        ROLE,
        MEDIUM,
        {"full_admin": False, "broad_statements": [{"has_condition": True}]},
        50,
        "INDIRECT/HIGH/MEDIUM",
    ),
    ("CS-CT-001", ACCOUNT, HIGH, NO_LOGGING, 55, "NONE/MODERATE/HIGH"),
    ("CS-CT-001", ACCOUNT, MEDIUM, SOME_LOGGING, 35, "NONE/LIMITED/HIGH"),
]


@pytest.mark.parametrize(
    ("rule_id", "resource_type", "severity", "evidence", "score", "levels"), WORKED_EXAMPLES
)
def test_worked_examples(
    rule_id: str,
    resource_type: str,
    severity: Severity,
    evidence: dict[str, Any],
    score: int,
    levels: str,
) -> None:
    risk = assess(rule_id, resource_type, severity, evidence)
    b = risk.breakdown
    assert f"{b['exposure']['level']}/{b['impact']['level']}/{b['confidence']['level']}" == levels
    assert risk.score == score


def test_breakdown_explains_every_point() -> None:
    risk = assess("CS-SG-001", SG, Severity.HIGH, ATTACHMENTS_UNKNOWN)
    b = risk.breakdown
    parts = [b[name]["points"] for name in ("severity", "exposure", "impact", "confidence")]
    assert parts == [40, 25, 20, -5]
    assert sum(parts) == risk.score == b["score"]
    assert b["model_version"] == RISK_MODEL_VERSION
    assert b["priority"] == "P1"
    assert all(b[name]["reason"] for name in ("exposure", "impact", "confidence"))


def test_same_input_always_gives_the_same_score() -> None:
    evidence = {"full_admin": True, "console_password": True, "active_access_keys": 2}
    results = {
        (r.score, str(r.breakdown))
        for r in (assess("CS-IAM-002", USER, Severity.HIGH, dict(evidence)) for _ in range(5))
    }
    assert len(results) == 1


def test_scores_stay_within_0_and_100() -> None:
    top = max(SEVERITY_POINTS.values()) + max(EXPOSURE_POINTS.values()) + max(
        IMPACT_POINTS.values()
    )
    bottom = min(SEVERITY_POINTS.values()) + min(IMPACT_POINTS.values()) + min(
        CONFIDENCE_POINTS.values()
    )
    assert top == 100  # the weights add up to exactly 100 at most
    assert bottom >= 0


def test_every_shipped_rule_has_a_risk_profile() -> None:
    assert {rule.id for rule in get_rule_catalog().rules} == set(PROFILES)


def test_a_rule_without_a_profile_gets_middle_values_with_low_confidence() -> None:
    risk = assess("CS-NEW-001", BUCKET, Severity.HIGH, {})
    assert risk.breakdown["confidence"]["level"] == "LOW"
    assert risk.score == 40 + 10 + 15 - 10


@pytest.mark.parametrize(
    ("score", "priority"),
    [(100, Priority.P1), (80, Priority.P1), (79, Priority.P2), (60, Priority.P2),
     (59, Priority.P3), (40, Priority.P3), (39, Priority.P4), (0, Priority.P4)],
)
def test_priority_bands(score: int, priority: Priority) -> None:
    assert priority_for(score) == priority


def test_summary() -> None:
    assert summarize([85, 35, 62, 80]) == {
        "model_version": RISK_MODEL_VERSION,
        "max_score": 85,
        "by_priority": {"P1": 2, "P2": 1, "P3": 0, "P4": 1},
    }
    assert summarize([])["max_score"] is None
