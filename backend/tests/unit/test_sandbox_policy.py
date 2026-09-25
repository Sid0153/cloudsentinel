"""sandbox/policy.py: the simulator's simplified bucket-policy check (GetBucketPolicyStatus).

The module lives in the sandbox image, outside the backend package, so it is loaded by path.
"""

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

POLICY_MODULE = Path(__file__).resolve().parents[3] / "sandbox" / "policy.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sandbox_policy", POLICY_MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = _load()


def _document(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _statement(principal: Any, effect: str = "Allow", **extra: Any) -> dict[str, Any]:
    return {
        "Effect": effect,
        "Principal": principal,
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::b/*",
        **extra,
    }


@pytest.mark.parametrize(
    ("document", "public"),
    [
        (None, False),
        ("", False),
        (_document(_statement("*")), True),
        (_document(_statement({"AWS": "*"})), True),
        (_document(_statement({"AWS": ["arn:aws:iam::123456789012:root", "*"]})), True),
        (_document(_statement({"AWS": "arn:aws:iam::123456789012:root"})), False),
        (_document(_statement("*", effect="Deny")), False),
        (
            _document(_statement("*", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})),
            False,
        ),
        # A single statement may be written as an object instead of a list.
        (json.dumps({"Statement": _statement("*")}), True),
    ],
)
def test_policy_is_public(document: str | None, public: bool) -> None:
    assert policy.policy_is_public(document) is public


def test_bytes_are_accepted() -> None:
    assert policy.policy_is_public(_document(_statement("*")).encode()) is True


def test_xml_answer_has_the_aws_shape() -> None:
    assert "<IsPublic>true</IsPublic>" in policy.policy_status_xml(True)
    assert "<IsPublic>false</IsPublic>" in policy.policy_status_xml(False)
