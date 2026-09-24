"""Computes a finding's risk score and explains every point of it. Pure and deterministic."""

from collections import Counter
from typing import Any

from app.risk.model import (
    CONFIDENCE_POINTS,
    EXPOSURE_POINTS,
    IMPACT_POINTS,
    MAX_SCORE,
    MIN_SCORE,
    RISK_MODEL_VERSION,
    SEVERITY_POINTS,
    Priority,
    RiskAssessment,
    priority_for,
)
from app.risk.profiles import PROFILES, fallback
from app.rules.model import Severity


def assess(
    rule_id: str, resource_type: str, severity: Severity, evidence: dict[str, Any]
) -> RiskAssessment:
    factors = PROFILES.get(rule_id, fallback)(resource_type, evidence)
    parts = {
        "severity": SEVERITY_POINTS[severity],
        "exposure": EXPOSURE_POINTS[factors.exposure],
        "impact": IMPACT_POINTS[factors.impact],
        "confidence": CONFIDENCE_POINTS[factors.confidence],
    }
    score = max(MIN_SCORE, min(MAX_SCORE, sum(parts.values())))
    priority = priority_for(score)
    breakdown = {
        "model_version": RISK_MODEL_VERSION,
        "score": score,
        "priority": str(priority),
        "severity": {"level": str(severity), "points": parts["severity"]},
        "exposure": {
            "level": str(factors.exposure),
            "points": parts["exposure"],
            "reason": factors.exposure_reason,
        },
        "impact": {
            "level": str(factors.impact),
            "points": parts["impact"],
            "reason": factors.impact_reason,
        },
        "confidence": {
            "level": str(factors.confidence),
            "points": parts["confidence"],
            "reason": factors.confidence_reason,
        },
    }
    return RiskAssessment(score=score, priority=priority, breakdown=breakdown)


def summarize(scores: list[int]) -> dict[str, Any]:
    """A scan's risk at a glance: its worst finding and how many fall in each priority band."""
    bands = Counter(str(priority_for(score)) for score in scores)
    return {
        "model_version": RISK_MODEL_VERSION,
        "max_score": max(scores) if scores else None,
        "by_priority": {str(p): bands.get(str(p), 0) for p in Priority},
    }
