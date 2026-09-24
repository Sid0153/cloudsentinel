"""CS-SG-001 (SSH), CS-SG-002 (RDP) and CS-SG-003 (broad inbound access)."""

import pytest

from app.domain.resources import IpPermission
from app.rules.checks.security_groups import (
    broad_inbound_access,
    unrestricted_rdp,
    unrestricted_ssh,
)
from app.rules.model import OutcomeStatus, RuleCheck, Severity
from tests.fixtures.resources import context, inbound, instance, security_group

ANYWHERE = ["0.0.0.0/0"]
ANYWHERE_V6 = ["::/0"]


def _status(check: RuleCheck, *rules: IpPermission) -> OutcomeStatus:
    group = security_group(*rules)
    return check.evaluate(group, context(group)).status


# --- CS-SG-001 / CS-SG-002 ---------------------------------------------------------------


def _opening_rules(port: int) -> list[IpPermission]:
    return [
        inbound("tcp", port, v4=ANYWHERE),  # exactly this port
        inbound("tcp", port - 10, port + 10, v4=ANYWHERE),  # a range that includes it
        inbound("-1", None, None, v4=ANYWHERE),  # all traffic
        inbound("tcp", 0, 65535, v6=ANYWHERE_V6),  # every TCP port, IPv6 only
    ]


OPEN_CASES = [(unrestricted_ssh, 22, rule) for rule in _opening_rules(22)] + [
    (unrestricted_rdp, 3389, rule) for rule in _opening_rules(3389)
]


@pytest.mark.parametrize(("check", "port", "rule"), OPEN_CASES)
def test_open_admin_port_fails(check: RuleCheck, port: int, rule: IpPermission) -> None:
    group = security_group(rule)
    outcome = check.evaluate(group, context(group))
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity is None  # the rule's default (HIGH) applies
    assert outcome.evidence["port"] == port
    assert outcome.evidence["attached_instance_ids"] == ["i-1"]


def test_ssh_evidence_describes_the_rule() -> None:
    group = security_group(inbound("tcp", 20, 25, v4=ANYWHERE, v6=ANYWHERE_V6))
    outcome = unrestricted_ssh.evaluate(group, context(group))
    assert outcome.evidence["open_rules"] == [
        {"protocol": "tcp", "ports": "20-25", "sources": ["0.0.0.0/0", "::/0"]}
    ]


@pytest.mark.parametrize(
    "rule",
    [
        inbound("tcp", 22, v4=["10.0.0.0/8"]),  # private range
        inbound("tcp", 22, v4=["203.0.113.10/32"]),  # a single office IP
        inbound("tcp", 22, v4=["0.0.0.0/1"]),  # wide, but not exactly "anywhere"
        inbound("tcp", 22, groups=["sg-bastion"]),  # from another security group
        inbound("udp", 22, v4=ANYWHERE),  # UDP, not SSH
        inbound("tcp", 23, 3388, v4=ANYWHERE),  # range that stops before 3389 / starts after 22
        inbound("icmp", -1, -1, v4=ANYWHERE),
    ],
)
def test_restricted_or_other_rules_pass_ssh_and_rdp(rule: IpPermission) -> None:
    assert _status(unrestricted_ssh, rule) == OutcomeStatus.PASS
    assert _status(unrestricted_rdp, rule) == OutcomeStatus.PASS


def test_group_without_inbound_rules_passes() -> None:
    assert _status(unrestricted_ssh) == OutcomeStatus.PASS


def test_unattached_group_still_fails_and_says_so() -> None:
    group = security_group(inbound("tcp", 22, v4=ANYWHERE), attached_instance_ids=[])
    outcome = unrestricted_ssh.evaluate(group, context(group))
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.evidence["attached_instance_ids"] == []
    assert outcome.evidence["attachments_known"] is True


# --- CS-SG-003 ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        inbound("tcp", 443, v4=ANYWHERE),
        inbound("tcp", 80, v4=ANYWHERE, v6=ANYWHERE_V6),
        inbound("tcp", 22, v4=ANYWHERE),  # reported by CS-SG-001 instead
        inbound("tcp", 3389, v4=ANYWHERE),  # reported by CS-SG-002 instead
        inbound("tcp", 5432, v4=["10.0.0.0/16"]),  # database, but only from the VPC
        inbound("icmp", -1, -1, v4=ANYWHERE),  # ping is ignored
    ],
)
def test_expected_or_non_public_access_passes(rule: IpPermission) -> None:
    assert _status(broad_inbound_access, rule) == OutcomeStatus.PASS


@pytest.mark.parametrize(
    ("rule", "severity"),
    [
        (inbound("tcp", 3306, v4=ANYWHERE), Severity.HIGH),  # MySQL
        (inbound("udp", 161, v4=ANYWHERE), Severity.HIGH),  # SNMP
        (inbound("tcp", 27017, v6=ANYWHERE_V6), Severity.HIGH),  # MongoDB over IPv6
        (inbound("-1", None, None, v4=ANYWHERE), Severity.HIGH),  # all traffic
        (inbound("tcp", 0, 65535, v4=ANYWHERE), Severity.HIGH),  # every TCP port
        (inbound("tcp", 8000, 8100, v4=ANYWHERE), Severity.MEDIUM),  # app ports
        (inbound("tcp", 8080, v4=ANYWHERE), Severity.MEDIUM),
        (inbound("tcp", 80, 443, v4=ANYWHERE), Severity.HIGH),  # range includes SMB, LDAP...
    ],
)
def test_broad_access_severity_depends_on_the_port(rule: IpPermission, severity: Severity) -> None:
    group = security_group(rule)
    outcome = broad_inbound_access.evaluate(group, context(group))
    assert outcome.status == OutcomeStatus.FAIL
    assert outcome.severity == severity


def test_broad_access_takes_the_worst_severity_and_lists_every_exposure() -> None:
    group = security_group(
        inbound("tcp", 8080, v4=ANYWHERE),
        inbound("tcp", 6379, v4=ANYWHERE),
        inbound("tcp", 443, v4=ANYWHERE),  # not an exposure
    )
    outcome = broad_inbound_access.evaluate(group, context(group))
    assert outcome.severity == Severity.HIGH
    exposures = outcome.evidence["exposures"]
    assert [e["ports"] for e in exposures] == ["8080", "6379"]
    assert exposures[0]["severity"] == "MEDIUM"
    assert exposures[1]["sensitive_services"] == ["Redis"]


def test_missing_ports_on_tcp_are_treated_as_all_ports() -> None:
    group = security_group(inbound("tcp", None, None, v4=ANYWHERE))
    outcome = broad_inbound_access.evaluate(group, context(group))
    assert outcome.severity == Severity.HIGH
    assert unrestricted_ssh.evaluate(group, context(group)).status == OutcomeStatus.FAIL


# --- Evidence used by the risk engine ----------------------------------------------------


def test_internet_facing_instances_are_running_with_a_public_ip_in_the_same_region() -> None:
    group = security_group(
        inbound("tcp", 22, v4=ANYWHERE), attached_instance_ids=["i-1", "i-2", "i-3", "i-4"]
    )
    instances = [
        instance("i-1"),  # running, public IP: internet-facing
        instance("i-2", public_ip=None),  # private only
        instance("i-3", state="stopped", public_ip=None),
        instance("i-4", region="eu-west-1"),  # same ID in another region: not this group's
        instance("i-9"),  # public, but not attached to the group
    ]
    outcome = unrestricted_ssh.evaluate(group, context(group, *instances))
    assert outcome.evidence["internet_facing_instance_ids"] == ["i-1"]
    assert outcome.evidence["attached_instance_ids"] == ["i-1", "i-2", "i-3", "i-4"]
