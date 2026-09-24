"""Loads rule metadata from YAML and pairs it with the Python checks.

Loading is strict on purpose: a missing field, an unknown severity, a metadata file without a
check or a check without a metadata file stops the application at startup instead of
producing findings with missing text.
"""

import enum
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.rules.model import Category, Reference, Rule, RuleCheck, RuleMetadata, Severity

RULE_ID_PATTERN = re.compile(r"^CS-[A-Z0-9]+-\d{3}$")
REQUIRED_TEXT = ("id", "title", "description", "rationale", "remediation")
OPTIONAL_TEXT = ("severity_note", "limitations")
KNOWN_KEYS = {*REQUIRED_TEXT, *OPTIONAL_TEXT, "category", "severity", "references"}


class RuleCatalogError(Exception):
    pass


@dataclass(frozen=True)
class RuleCatalog:
    rules: list[Rule]  # sorted by rule ID

    def get(self, rule_id: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)


def _text(data: dict[str, Any], key: str, source: str, required: bool) -> str | None:
    value = data.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuleCatalogError(f"{source}: '{key}' must be a non-empty string")
    return value.strip()


def _enum[E: enum.StrEnum](enum_type: type[E], data: dict[str, Any], key: str, source: str) -> E:
    try:
        return enum_type(str(data.get(key)))
    except ValueError:
        allowed = ", ".join(member.value for member in enum_type)
        raise RuleCatalogError(f"{source}: '{key}' must be one of {allowed}") from None


def _references(data: dict[str, Any], source: str) -> list[Reference]:
    raw = data.get("references") or []
    if not isinstance(raw, list):
        raise RuleCatalogError(f"{source}: 'references' must be a list")
    references: list[Reference] = []
    for item in raw:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) for key in ("title", "url")
        ):
            raise RuleCatalogError(f"{source}: each reference needs a 'title' and a 'url'")
        if not item["url"].startswith("https://"):
            raise RuleCatalogError(f"{source}: reference URLs must use https")
        references.append(Reference(title=item["title"], url=item["url"]))
    return references


def parse_metadata(data: Any, source: str) -> RuleMetadata:
    if not isinstance(data, dict):
        raise RuleCatalogError(f"{source}: expected a mapping at the top level")
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        raise RuleCatalogError(f"{source}: unknown keys {sorted(unknown)}")
    text = {key: _text(data, key, source, required=True) for key in REQUIRED_TEXT}
    rule_id = str(text["id"])
    if not RULE_ID_PATTERN.match(rule_id):
        raise RuleCatalogError(f"{source}: rule id '{rule_id}' does not match CS-<AREA>-<NNN>")
    return RuleMetadata(
        id=rule_id,
        title=str(text["title"]),
        category=_enum(Category, data, "category", source),
        severity=_enum(Severity, data, "severity", source),
        description=str(text["description"]),
        rationale=str(text["rationale"]),
        remediation=str(text["remediation"]),
        severity_note=_text(data, "severity_note", source, required=False),
        limitations=_text(data, "limitations", source, required=False),
        references=_references(data, source),
    )


def load_metadata(directory: Path) -> dict[str, RuleMetadata]:
    if not directory.is_dir():
        raise RuleCatalogError(f"Rule metadata directory not found: {directory}")
    metadata: dict[str, RuleMetadata] = {}
    for path in sorted(directory.glob("*.yaml")):
        # safe_load only builds plain data (dicts, lists, strings); it never runs code.
        with path.open(encoding="utf-8") as handle:
            item = parse_metadata(yaml.safe_load(handle), path.name)
        if path.stem != item.id:
            raise RuleCatalogError(f"{path.name}: file name must match the rule id '{item.id}'")
        metadata[item.id] = item
    return metadata


def build_catalog(metadata: dict[str, RuleMetadata], checks: list[RuleCheck]) -> RuleCatalog:
    check_ids = [c.rule_id for c in checks]
    duplicates = {rule_id for rule_id in check_ids if check_ids.count(rule_id) > 1}
    if duplicates:
        raise RuleCatalogError(f"More than one check for {sorted(duplicates)}")
    missing_metadata = set(check_ids) - set(metadata)
    missing_checks = set(metadata) - set(check_ids)
    if missing_metadata:
        raise RuleCatalogError(f"Checks without a metadata file: {sorted(missing_metadata)}")
    if missing_checks:
        raise RuleCatalogError(f"Metadata files without a check: {sorted(missing_checks)}")
    rules = [Rule(metadata=metadata[c.rule_id], check=c) for c in checks]
    return RuleCatalog(rules=sorted(rules, key=lambda rule: rule.id))


def load_catalog(directory: Path, checks: list[RuleCheck]) -> RuleCatalog:
    return build_catalog(load_metadata(directory), checks)
