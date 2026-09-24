"""CS-CT-001: a multi-region trail must be logging. Evaluated once, on the account."""

from app.domain.coverage import CoverageStatus
from app.domain.resources import NormalizedResource
from app.rules.checks.cloudtrail import no_multi_region_logging_trail
from app.rules.model import Outcome, OutcomeStatus, Severity
from tests.fixtures.resources import account, context, full_coverage, trail


def _evaluate(*trails: NormalizedResource, cloudtrail_status: str = "SUCCEEDED") -> Outcome:
    coverage = full_coverage()
    coverage["cloudtrail"]["status"] = cloudtrail_status
    target = account()
    return no_multi_region_logging_trail.evaluate(
        target, context(target, *trails, coverage=coverage)
    )


def test_multi_region_logging_trail_passes() -> None:
    assert _evaluate(trail()).status == OutcomeStatus.PASS


def test_one_good_trail_is_enough_even_with_other_problems() -> None:
    outcome = _evaluate(
        trail("stopped", is_logging=False),
        trail("good"),
        cloudtrail_status=CoverageStatus.PARTIAL,  # a region failed, but we already have proof
    )
    assert outcome.status == OutcomeStatus.PASS


def test_no_trail_at_all_is_high() -> None:
    outcome = _evaluate()
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == Severity.HIGH
    assert outcome.evidence["trail_count"] == 0


def test_stopped_multi_region_trail_is_high() -> None:
    outcome = _evaluate(trail(is_logging=False))
    assert outcome.severity == Severity.HIGH
    assert outcome.evidence["trails"][0]["logging"] is False


def test_only_single_region_logging_is_medium() -> None:
    outcome = _evaluate(trail(is_multi_region=False))
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == Severity.MEDIUM
    assert outcome.evidence["some_single_region_trail_logging"] is True


def test_unreadable_status_of_a_multi_region_trail_is_unknown() -> None:
    assert _evaluate(trail(is_logging=None)).status == OutcomeStatus.UNKNOWN


def test_no_trail_found_but_trails_not_fully_read_is_unknown() -> None:
    for status in (CoverageStatus.PARTIAL, CoverageStatus.FAILED):
        assert _evaluate(cloudtrail_status=status).status == OutcomeStatus.UNKNOWN
