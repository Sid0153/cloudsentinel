"""The building blocks of a security rule.

A rule has two halves:
- metadata (title, severity, description, remediation...) in security-rules/rules/<id>.yaml,
  so the text can be reviewed and edited without touching code;
- a check: a plain Python function that looks at one normalized resource and returns an
  Outcome (PASS, FAIL with evidence, or UNKNOWN when the data needed is missing).
"""

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.domain.coverage import Coverage, type_fully_read
from app.domain.resources import NormalizedResource, ResourceType


class Severity(enum.StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        """Higher is worse. Used for sorting and for picking the worst of several issues."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def worst(severities: list[Severity]) -> Severity:
    return max(severities, key=lambda severity: severity.rank)


class Category(enum.StrEnum):
    NETWORK = "NETWORK"
    DATA_PROTECTION = "DATA_PROTECTION"
    IDENTITY = "IDENTITY"
    LOGGING = "LOGGING"


@dataclass(frozen=True)
class Reference:
    title: str
    url: str


@dataclass(frozen=True)
class RuleMetadata:
    """Human-facing description of a rule, loaded from YAML."""

    id: str
    title: str
    category: Category
    severity: Severity  # the default; a check may raise or lower it with a documented reason
    description: str  # what the rule detects
    rationale: str  # why it matters
    remediation: str  # how to fix it (instructions only; CloudSentinel never changes AWS)
    severity_note: str | None = None  # when and why the severity differs from the default
    limitations: str | None = None  # what the check does NOT look at
    references: list[Reference] = field(default_factory=list)


class OutcomeStatus(enum.StrEnum):
    # evaluated and compliant, or the rule does not apply to this resource
    PASS = "PASS"  # noqa: S105  (a status name, not a password)
    FAIL = "FAIL"  # evaluated and non-compliant: becomes a finding
    UNKNOWN = "UNKNOWN"  # could not be decided, e.g. a required AWS call was denied


@dataclass(frozen=True)
class Outcome:
    status: OutcomeStatus
    evidence: dict[str, Any] = field(default_factory=dict)
    severity: Severity | None = None  # None: use the rule's default severity
    reason: str | None = None  # for UNKNOWN: which data was missing

    @classmethod
    def passed(cls) -> "Outcome":
        return cls(OutcomeStatus.PASS)

    @classmethod
    def failed(cls, evidence: dict[str, Any], severity: Severity | None = None) -> "Outcome":
        return cls(OutcomeStatus.FAIL, evidence=evidence, severity=severity)

    @classmethod
    def unknown(cls, reason: str) -> "Outcome":
        return cls(OutcomeStatus.UNKNOWN, reason=reason)


@dataclass(frozen=True)
class RuleContext:
    """Everything a check may look at besides the resource itself.

    Most checks only need the resource. Account-wide checks (such as "is there a CloudTrail
    trail?") read the other resources and the coverage of the scan.
    """

    resources: list[NormalizedResource]
    coverage: Coverage

    def of_type(self, resource_type: ResourceType) -> list[NormalizedResource]:
        return [r for r in self.resources if r.resource_type == resource_type]

    def fully_read(self, resource_type: ResourceType) -> bool:
        return type_fully_read(self.coverage, resource_type)


CheckFunction = Callable[[NormalizedResource, RuleContext], Outcome]


@dataclass(frozen=True)
class RuleCheck:
    rule_id: str
    resource_types: tuple[ResourceType, ...]
    evaluate: CheckFunction


def check(rule_id: str, *resource_types: ResourceType) -> Callable[[CheckFunction], RuleCheck]:
    """Decorator that turns a check function into a RuleCheck. It registers nothing globally:
    app/rules/registry.py lists every check explicitly."""

    def wrap(function: CheckFunction) -> RuleCheck:
        return RuleCheck(rule_id=rule_id, resource_types=resource_types, evaluate=function)

    return wrap


@dataclass(frozen=True)
class Rule:
    metadata: RuleMetadata
    check: RuleCheck

    @property
    def id(self) -> str:
        return self.metadata.id

    @property
    def resource_types(self) -> tuple[ResourceType, ...]:
        return self.check.resource_types


def config_of[ConfigT](resource: NormalizedResource, config_type: type[ConfigT]) -> ConfigT:
    """The resource's configuration, checked to be of the type the rule expects."""
    config = resource.config
    if not isinstance(config, config_type):
        raise TypeError(
            f"{resource.resource_type} {resource.resource_id} has no {config_type.__name__}"
        )
    return config
