"""Security group rules: inbound access from the whole internet.

"The internet" means exactly 0.0.0.0/0 or ::/0. Other wide ranges (for example 0.0.0.0/1),
prefix lists and security-group sources are not treated as public. Outbound rules are not
checked. Whether the group is attached to an instance is recorded as evidence, not used to
decide pass or fail: an unattached open group is one attachment away from being exposed.
"""

from typing import Any

from app.domain.resources import (
    IpPermission,
    NormalizedResource,
    ResourceType,
    SecurityGroupConfig,
)
from app.rules.model import Outcome, RuleContext, Severity, check, config_of, worst

INTERNET_V4 = "0.0.0.0/0"
INTERNET_V6 = "::/0"
ALL_PORTS = (0, 65535)

SSH_PORT = 22
RDP_PORT = 3389
# Serving a website to everyone is normal, so these single ports are not flagged.
WEB_PORTS = {80, 443}

# Services that should almost never be reachable from the whole internet. Exposing any of
# them makes a broad-access finding HIGH instead of MEDIUM.
SENSITIVE_PORTS: dict[int, str] = {
    20: "FTP data",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    135: "Windows RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    161: "SNMP",
    389: "LDAP",
    445: "SMB",
    1433: "SQL Server",
    1521: "Oracle",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    3306: "MySQL",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def internet_sources(permission: IpPermission) -> list[str]:
    sources = [c for c in permission.cidrs_v4 if c == INTERNET_V4]
    sources += [c for c in permission.cidrs_v6 if c == INTERNET_V6]
    return sources


def port_range(permission: IpPermission) -> tuple[int, int] | None:
    """The (first, last) port a rule opens, or None for protocols without ports (ICMP...)."""
    if permission.protocol == "-1":
        return ALL_PORTS
    if permission.protocol not in ("tcp", "udp"):
        return None
    if permission.from_port is None or permission.to_port is None:
        return ALL_PORTS  # not expected from EC2 for tcp/udp; assume the worst
    return (permission.from_port, permission.to_port)


def _ports_label(ports: tuple[int, int]) -> str:
    first, last = ports
    return str(first) if first == last else f"{first}-{last}"


def describe(
    permission: IpPermission, ports: tuple[int, int], sources: list[str]
) -> dict[str, Any]:
    return {
        "protocol": "all" if permission.protocol == "-1" else permission.protocol,
        "ports": "all" if permission.protocol == "-1" else _ports_label(ports),
        "sources": sources,
    }


def attachment_evidence(group: SecurityGroupConfig) -> dict[str, Any]:
    return {
        "attached_instance_ids": group.attached_instance_ids,
        "attachments_known": group.attachments_known,
    }


def rules_opening_tcp_port(group: SecurityGroupConfig, port: int) -> list[dict[str, Any]]:
    """Inbound rules that let the whole internet reach a TCP port (directly or in a range)."""
    found: list[dict[str, Any]] = []
    for permission in group.inbound:
        sources = internet_sources(permission)
        ports = port_range(permission)
        if not sources or ports is None or permission.protocol not in ("tcp", "-1"):
            continue
        if ports[0] <= port <= ports[1]:
            found.append(describe(permission, ports, sources))
    return found


def _open_port_check(resource: NormalizedResource, port: int) -> Outcome:
    group = config_of(resource, SecurityGroupConfig)
    open_rules = rules_opening_tcp_port(group, port)
    if not open_rules:
        return Outcome.passed()
    return Outcome.failed({"port": port, "open_rules": open_rules, **attachment_evidence(group)})


@check("CS-SG-001", ResourceType.SECURITY_GROUP)
def unrestricted_ssh(resource: NormalizedResource, context: RuleContext) -> Outcome:
    return _open_port_check(resource, SSH_PORT)


@check("CS-SG-002", ResourceType.SECURITY_GROUP)
def unrestricted_rdp(resource: NormalizedResource, context: RuleContext) -> Outcome:
    return _open_port_check(resource, RDP_PORT)


def _is_covered_elsewhere(ports: tuple[int, int]) -> bool:
    """A single web port is expected; a single SSH/RDP port is reported by CS-SG-001/002."""
    first, last = ports
    return first == last and first in WEB_PORTS | {SSH_PORT, RDP_PORT}


def sensitive_services(ports: tuple[int, int]) -> list[str]:
    first, last = ports
    names = {name for port, name in SENSITIVE_PORTS.items() if first <= port <= last}
    return sorted(names)


def classify_exposure(permission: IpPermission, ports: tuple[int, int]) -> Severity:
    if permission.protocol == "-1" or ports == ALL_PORTS or ports == (1, 65535):
        return Severity.HIGH
    if sensitive_services(ports):
        return Severity.HIGH
    return Severity.MEDIUM


@check("CS-SG-003", ResourceType.SECURITY_GROUP)
def broad_inbound_access(resource: NormalizedResource, context: RuleContext) -> Outcome:
    group = config_of(resource, SecurityGroupConfig)
    exposures: list[dict[str, Any]] = []
    severities: list[Severity] = []
    for permission in group.inbound:
        sources = internet_sources(permission)
        ports = port_range(permission)
        if not sources or ports is None or _is_covered_elsewhere(ports):
            continue
        severity = classify_exposure(permission, ports)
        severities.append(severity)
        exposures.append(
            {
                **describe(permission, ports, sources),
                "sensitive_services": sensitive_services(ports),
                "severity": str(severity),
            }
        )
    if not exposures:
        return Outcome.passed()
    evidence = {"exposures": exposures, **attachment_evidence(group)}
    return Outcome.failed(evidence, severity=worst(severities))
