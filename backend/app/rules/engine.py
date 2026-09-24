"""Runs every rule against every resource it applies to. Pure: no AWS, no database.

For each rule the engine also produces a summary (the scan's "rule_results"), so a rule that
could not be fully evaluated is reported as INCOMPLETE, never as PASSED. A check that raises
an exception is reported as ERROR and does not stop the other rules.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from app.domain.coverage import Coverage
from app.domain.resources import NormalizedResource, ResourceKey, resource_key
from app.rules.model import Outcome, OutcomeStatus, Rule, RuleContext, Severity

logger = logging.getLogger(__name__)

MAX_UNKNOWN_SAMPLES = 10
ERROR_REASON = "internal error in the rule (details are in the server log)"


class RuleResultStatus:
    FAILED = "FAILED"  # at least one finding
    PASSED = "PASSED"  # every applicable resource evaluated and compliant, coverage complete
    INCOMPLETE = "INCOMPLETE"  # no findings, but some resources could not be evaluated
    NOT_APPLICABLE = "NOT_APPLICABLE"  # no resources of this type exist (coverage complete)
    ERROR = "ERROR"  # the check raised an exception for at least one resource


@dataclass(frozen=True)
class Detection:
    rule: Rule
    resource: NormalizedResource
    severity: Severity
    evidence: dict[str, Any]


@dataclass
class Evaluation:
    detections: list[Detection] = field(default_factory=list)
    # (rule ID, resource key) pairs that were evaluated and compliant. Only these may close
    # an existing finding.
    passed: set[tuple[str, ResourceKey]] = field(default_factory=set)
    rule_results: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def had_errors(self) -> bool:
        return any(r["status"] == RuleResultStatus.ERROR for r in self.rule_results.values())


def _safe_evaluate(
    rule: Rule, resource: NormalizedResource, context: RuleContext
) -> Outcome | None:
    """The check's outcome, or None if the check crashed (a bug, logged with its traceback)."""
    try:
        return rule.check.evaluate(resource, context)
    except Exception:
        logger.exception("Rule %s failed on %s", rule.id, resource.resource_id)
        return None


def _summary_status(
    counts: dict[OutcomeStatus, int], errors: int, coverage_complete: bool
) -> str:
    if errors:
        return RuleResultStatus.ERROR
    if counts[OutcomeStatus.FAIL]:
        return RuleResultStatus.FAILED
    if counts[OutcomeStatus.UNKNOWN] or not coverage_complete:
        return RuleResultStatus.INCOMPLETE
    if counts[OutcomeStatus.PASS] == 0:
        return RuleResultStatus.NOT_APPLICABLE
    return RuleResultStatus.PASSED


def evaluate_rule(rule: Rule, context: RuleContext, evaluation: Evaluation) -> None:
    counts = {status: 0 for status in OutcomeStatus}
    unknown_samples: list[dict[str, str]] = []
    errors = 0
    for resource in context.resources:
        if resource.resource_type not in rule.resource_types:
            continue
        outcome = _safe_evaluate(rule, resource, context)
        if outcome is None:
            errors += 1
            outcome = Outcome.unknown(ERROR_REASON)
        counts[outcome.status] += 1
        if outcome.status == OutcomeStatus.FAIL:
            evaluation.detections.append(
                Detection(
                    rule=rule,
                    resource=resource,
                    severity=outcome.severity or rule.metadata.severity,
                    evidence=outcome.evidence,
                )
            )
        elif outcome.status == OutcomeStatus.PASS:
            evaluation.passed.add((rule.id, resource_key(resource)))
        elif len(unknown_samples) < MAX_UNKNOWN_SAMPLES:
            unknown_samples.append(
                {"resource_id": resource.resource_id, "reason": outcome.reason or "unknown"}
            )

    coverage_complete = all(context.fully_read(t) for t in rule.resource_types)
    evaluation.rule_results[rule.id] = {
        "status": _summary_status(counts, errors, coverage_complete),
        "evaluated": sum(counts.values()),
        "passed": counts[OutcomeStatus.PASS],
        "failed": counts[OutcomeStatus.FAIL],
        "unknown": counts[OutcomeStatus.UNKNOWN],
        "coverage_complete": coverage_complete,
        "unknown_samples": unknown_samples,
    }


def evaluate(
    rules: list[Rule], resources: list[NormalizedResource], coverage: Coverage
) -> Evaluation:
    context = RuleContext(resources=resources, coverage=coverage)
    evaluation = Evaluation()
    for rule in rules:
        evaluate_rule(rule, context, evaluation)
    return evaluation
