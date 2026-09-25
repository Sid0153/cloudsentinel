"""The sandbox environment and its switches, against moto's in-process mock.

The most important property: each switch makes exactly its own rule fail, and nothing else,
so what a visitor changes is what the next scan reports.
"""

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError

from app.aws.sandbox import (
    CONTROLS,
    CONTROLS_BY_KEY,
    SANDBOX_REGION,
    Clients,
    apply_defaults,
    clients_for,
    ensure_environment,
    read_states,
)
from app.aws.session import get_caller_identity
from app.core.config import get_settings
from app.rules.engine import evaluate
from app.scans.discovery import discover
from app.services import sandbox as sandbox_service
from app.services.rule_catalog import get_rule_catalog

DEFAULTS = {control.key: control.insecure_by_default for control in CONTROLS}


@pytest.fixture
def clients(mocked_aws: None, policy_status: dict[str, bool]) -> Clients:
    clients = clients_for(boto3.Session(region_name=SANDBOX_REGION))
    assert ensure_environment(clients) is True
    return clients


def _failing_rules(clients: Clients) -> set[str]:
    session = boto3.Session(region_name=SANDBOX_REGION)
    discovery = discover(session, get_caller_identity(session), [SANDBOX_REGION])
    assert discovery.complete, discovery.coverage
    evaluation = evaluate(get_rule_catalog().rules, discovery.resources, discovery.coverage)
    statuses = {rule_id: result["status"] for rule_id, result in evaluation.rule_results.items()}
    assert "INCOMPLETE" not in statuses.values() and "ERROR" not in statuses.values()
    return {rule_id for rule_id, status in statuses.items() if status == "FAILED"}


def test_environment_is_created_once_with_the_default_switches(clients: Clients) -> None:
    assert ensure_environment(clients) is False  # already there
    assert read_states(clients) == DEFAULTS


def test_every_rule_can_be_triggered() -> None:
    assert {control.rule_id for control in CONTROLS} == {
        rule.id for rule in get_rule_catalog().rules
    }


def test_defaults_fail_exactly_the_default_rules(clients: Clients) -> None:
    expected = {control.rule_id for control in CONTROLS if control.insecure_by_default}
    assert _failing_rules(clients) == expected


@pytest.mark.parametrize("key", sorted(CONTROLS_BY_KEY))
def test_each_switch_changes_only_its_own_rule(clients: Clients, key: str) -> None:
    control = CONTROLS_BY_KEY[key]
    before = _failing_rules(clients)

    control.set_insecure(clients, not control.insecure_by_default)
    assert read_states(clients) == {**DEFAULTS, key: not control.insecure_by_default}
    assert _failing_rules(clients) ^ before == {control.rule_id}

    control.set_insecure(clients, control.insecure_by_default)
    assert read_states(clients) == DEFAULTS


def test_switches_are_idempotent(clients: Clients) -> None:
    for control in CONTROLS:
        for _ in range(2):
            control.set_insecure(clients, True)
        assert control.is_insecure(clients)
        for _ in range(2):
            control.set_insecure(clients, False)
        assert not control.is_insecure(clients)


def test_reset_restores_the_defaults(clients: Clients) -> None:
    for control in CONTROLS:
        control.set_insecure(clients, not control.insecure_by_default)
    apply_defaults(clients)
    assert read_states(clients) == DEFAULTS


def test_prepare_for_scan_does_nothing_in_normal_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_settings: object) -> None:
        raise AssertionError("must not build sandbox clients in normal mode")

    monkeypatch.setattr(sandbox_service, "clients_for", fail)
    sandbox_service.prepare_for_scan(get_settings())


def test_prepare_for_scan_recreates_a_lost_environment(
    mocked_aws: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = clients_for(boto3.Session(region_name=SANDBOX_REGION))
    monkeypatch.setattr(sandbox_service, "sandbox_clients", lambda _settings: clients)
    sandbox_service.prepare_for_scan(get_settings())
    assert read_states(clients) == DEFAULTS


def test_prepare_for_scan_survives_an_unreachable_simulator(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def unreachable(_clients: Clients) -> bool:
        raise EndpointConnectionError(endpoint_url="http://sandbox-aws:5000")

    monkeypatch.setattr(sandbox_service, "sandbox_clients", lambda _settings: object())
    monkeypatch.setattr(sandbox_service, "ensure_environment", unreachable)
    sandbox_service.prepare_for_scan(get_settings())  # must not raise
    assert "could not be prepared" in caplog.text
