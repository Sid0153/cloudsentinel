"""The risk model's building blocks: factor levels, their points, and the result.

    risk = severity points + exposure points + impact points + confidence adjustment
           (clamped to 0-100)

Every number lives in the tables below, so the model can be read (and argued with) in one
place. docs/risk-model.md explains the choices. This is CloudSentinel's own model, not CVSS or
any other industry standard.
"""

import enum
from dataclasses import dataclass
from typing import Any

from app.rules.model import Severity

RISK_MODEL_VERSION = 1  # stored with every score; bump it when any number below changes
MIN_SCORE = 0
MAX_SCORE = 100

SEVERITY_POINTS: dict[Severity, int] = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 40,
    Severity.MEDIUM: 25,
    Severity.LOW: 10,
}


class Exposure(enum.StrEnum):
    """How an attacker reaches the problem."""

    INTERNET = "INTERNET"  # anyone on the internet, right now
    CONSOLE_LOGIN = "CONSOLE_LOGIN"  # the public AWS sign-in page; only a password stands
    CREDENTIALS = "CREDENTIALS"  # needs this identity's password or access keys
    INDIRECT = "INDIRECT"  # needs another foothold first (a workload using the role, a
    # private instance behind something else)
    LATENT = "LATENT"  # not reachable now, but one change away (e.g. an unattached group)
    NONE = "NONE"  # not an entry point (encryption at rest, missing logs)


EXPOSURE_POINTS: dict[Exposure, int] = {
    Exposure.INTERNET: 25,
    Exposure.CONSOLE_LOGIN: 20,
    Exposure.CREDENTIALS: 15,
    Exposure.INDIRECT: 10,
    Exposure.LATENT: 5,
    Exposure.NONE: 0,
}


class Impact(enum.StrEnum):
    """What an attacker gets if the problem is exploited."""

    SEVERE = "SEVERE"  # control of the account, or of data (tampering / arbitrary write)
    HIGH = "HIGH"  # a host shell, or reading data
    MODERATE = "MODERATE"  # a foothold with limited permissions, or lost audit trail
    LIMITED = "LIMITED"  # a small, indirect or defence-in-depth loss


IMPACT_POINTS: dict[Impact, int] = {
    Impact.SEVERE: 25,
    Impact.HIGH: 20,
    Impact.MODERATE: 15,
    Impact.LIMITED: 10,
}


class Confidence(enum.StrEnum):
    """How complete the evidence behind the exposure and impact decisions is."""

    HIGH = "HIGH"  # everything needed was read
    MEDIUM = "MEDIUM"  # one input was missing and a cautious assumption was made
    LOW = "LOW"  # no risk profile for this rule; generic values were used


CONFIDENCE_POINTS: dict[Confidence, int] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: -5,
    Confidence.LOW: -10,
}


class Priority(enum.StrEnum):
    """Score bands, named P1-P4 so they are not confused with a rule's severity."""

    P1 = "P1"  # 80-100: fix now
    P2 = "P2"  # 60-79: fix soon
    P3 = "P3"  # 40-59: plan a fix
    P4 = "P4"  # 0-39: fix when convenient


PRIORITY_THRESHOLDS: list[tuple[int, Priority]] = [
    (80, Priority.P1),
    (60, Priority.P2),
    (40, Priority.P3),
    (0, Priority.P4),
]


def priority_for(score: int) -> Priority:
    return next(priority for threshold, priority in PRIORITY_THRESHOLDS if score >= threshold)


@dataclass(frozen=True)
class RiskFactors:
    """A rule profile's judgement for one finding, each with a human-readable reason."""

    exposure: Exposure
    exposure_reason: str
    impact: Impact
    impact_reason: str
    confidence: Confidence = Confidence.HIGH
    confidence_reason: str = "All inputs were available"


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    priority: Priority
    breakdown: dict[str, Any]  # stored with the finding; explains every point
