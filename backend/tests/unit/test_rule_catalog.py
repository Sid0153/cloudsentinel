"""The rule catalog: the shipped YAML files, and strict validation of broken ones."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from app.core.config import DEFAULT_RULES_DIR
from app.rules.catalog import RuleCatalogError, load_catalog, load_metadata, parse_metadata
from app.rules.model import Severity
from app.rules.registry import ALL_CHECKS
from app.services.rule_catalog import get_rule_catalog

VALID: dict[str, Any] = {
    "id": "CS-SG-001",
    "title": "Title",
    "category": "NETWORK",
    "severity": "HIGH",
    "description": "What it detects",
    "rationale": "Why it matters",
    "remediation": "How to fix it",
    "references": [{"title": "Docs", "url": "https://docs.aws.amazon.com/"}],
}


def test_shipped_catalog_has_the_eight_rules_with_complete_text() -> None:
    rules = get_rule_catalog().rules
    assert [r.id for r in rules] == [
        "CS-CT-001",
        "CS-IAM-001",
        "CS-IAM-002",
        "CS-S3-001",
        "CS-S3-002",
        "CS-SG-001",
        "CS-SG-002",
        "CS-SG-003",
    ]
    for rule in rules:
        metadata = rule.metadata
        assert metadata.title and metadata.rationale and metadata.remediation
        assert metadata.limitations, f"{rule.id} should document what it does not check"
        assert metadata.references, f"{rule.id} should link to AWS documentation"
        assert rule.resource_types


def test_brief_severities_are_respected() -> None:
    catalog = get_rule_catalog()
    for rule_id in ("CS-SG-001", "CS-SG-002"):
        rule = catalog.get(rule_id)
        assert rule is not None and rule.metadata.severity == Severity.HIGH
    encryption = catalog.get("CS-S3-002")
    assert encryption is not None and encryption.metadata.severity == Severity.MEDIUM


def test_default_directory_points_at_the_repository_rules() -> None:
    assert DEFAULT_RULES_DIR.is_dir()
    assert (DEFAULT_RULES_DIR / "CS-SG-001.yaml").is_file()


def _write(directory: Path, data: Any, name: str = "CS-SG-001.yaml") -> None:
    (directory / name).write_text(yaml.safe_dump(data), encoding="utf-8")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"severity": "SEVERE"}, "'severity' must be one of"),
        ({"category": None}, "'category' must be one of"),
        ({"title": ""}, "'title' must be a non-empty string"),
        ({"remediation": None}, "'remediation' must be a non-empty string"),
        ({"id": "ssh-rule"}, "does not match"),
        ({"owner": "me"}, "unknown keys"),
        ({"references": [{"title": "x", "url": "http://insecure.example"}]}, "https"),
        ({"references": [{"title": "x"}]}, "'title' and a 'url'"),
    ],
)
def test_invalid_metadata_is_rejected(change: dict[str, Any], message: str) -> None:
    with pytest.raises(RuleCatalogError, match=message):
        parse_metadata({**VALID, **change}, "test.yaml")


def test_file_name_must_match_the_rule_id(tmp_path: Path) -> None:
    _write(tmp_path, VALID, name="CS-SG-009.yaml")
    with pytest.raises(RuleCatalogError, match="file name must match"):
        load_metadata(tmp_path)


def test_python_objects_in_yaml_are_refused(tmp_path: Path) -> None:
    """safe_load: a YAML file cannot make the loader run code."""
    (tmp_path / "CS-SG-001.yaml").write_text(
        "id: !!python/object/apply:os.system ['echo hacked']\n", encoding="utf-8"
    )
    with pytest.raises(yaml.YAMLError):
        load_metadata(tmp_path)


def test_every_check_needs_metadata_and_every_metadata_needs_a_check(tmp_path: Path) -> None:
    _write(tmp_path, VALID)
    with pytest.raises(RuleCatalogError, match="Checks without a metadata file"):
        load_catalog(tmp_path, ALL_CHECKS)

    _write(tmp_path, {**VALID, "id": "CS-XX-001"}, name="CS-XX-001.yaml")
    with pytest.raises(RuleCatalogError, match="Metadata files without a check"):
        load_catalog(tmp_path, [c for c in ALL_CHECKS if c.rule_id == "CS-SG-001"])


def test_duplicate_checks_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path, VALID)
    ssh = next(c for c in ALL_CHECKS if c.rule_id == "CS-SG-001")
    with pytest.raises(RuleCatalogError, match="More than one check"):
        load_catalog(tmp_path, [ssh, ssh])


def test_missing_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(RuleCatalogError, match="not found"):
        load_metadata(tmp_path / "nope")
