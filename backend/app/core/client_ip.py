"""Which address a request came from, for the rate limits and the audit log.

Proxies append to X-Forwarded-For, so its left part is whatever the client chose to send and
can be anything. Only entries added by our own proxies can be trusted, so the header is read
from the right. Two ways to say which entries are ours:

- TRUSTED_PROXY_HOPS=N: exactly N proxies append to the header (docker compose: nginx, 1).
  The N-th entry from the right is the address the outermost one saw.
- TRUSTED_PROXIES=networks: the chain has a variable length (Render: a request through the
  static site's /api rewrite passes Cloudflare, Render's proxy and Cloudflare again; a
  direct request passes fewer). Walking from the right, every address inside a trusted
  network is a proxy; the first one outside is the client ("rightmost untrusted"). Entries
  further left are never read, so forged ones cannot matter.

Without either setting, the direct peer address is used and X-Forwarded-For is ignored.
"""

import ipaddress
from ipaddress import IPv4Network, IPv6Network

from starlette.datastructures import Headers

Network = IPv4Network | IPv6Network

# Named groups for TRUSTED_PROXIES.
PRESET_NETWORKS: dict[str, tuple[str, ...]] = {
    # Private and loopback addresses: hosting platforms' internal load balancers.
    "private": (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "::1/128",
    ),
    # Cloudflare's published ranges (https://www.cloudflare.com/ips/, checked September 2026).
    "cloudflare": (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ),
}

# Headers that proxies and CDNs use for the client address. LOG_FORWARDING_HEADERS logs them,
# to find out what a hosting platform really sends before trusting any of it.
FORWARDING_HEADERS = (
    "x-forwarded-for",
    "true-client-ip",
    "cf-connecting-ip",
    "x-real-ip",
    "forwarded",
)
_MAX_LOGGED_LENGTH = 200


def parse_trusted_proxies(value: str) -> tuple[Network, ...]:
    """'private, cloudflare, 74.220.48.0/20' -> networks. Raises ValueError on bad input."""
    networks: list[Network] = []
    for token in (part.strip() for part in value.split(",")):
        if not token:
            continue
        for cidr in PRESET_NETWORKS.get(token.lower(), (token,)):
            networks.append(ipaddress.ip_network(cidr, strict=True))
    return tuple(networks)


def forwarding_headers(peer: str | None, headers: Headers) -> dict[str, str | None]:
    """The direct peer and every forwarding header present (truncated), for diagnostics."""
    found: dict[str, str | None] = {"peer": peer}
    for name in FORWARDING_HEADERS:
        values = headers.getlist(name)
        if values:
            found[name] = ", ".join(values)[:_MAX_LOGGED_LENGTH]
    return found


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _forwarded_for(headers: Headers) -> list[str]:
    return [
        entry.strip()
        for line in headers.getlist("x-forwarded-for")
        for entry in line.split(",")
        if entry.strip()
    ]


def _is_trusted(address: str, networks: tuple[Network, ...]) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip.version == network.version and ip in network for network in networks)


def _rightmost_untrusted(
    peer: str | None, headers: Headers, networks: tuple[Network, ...]
) -> str | None:
    if peer is None or _valid_ip(peer) is None or not _is_trusted(peer, networks):
        return peer  # not reached through a trusted proxy: its headers mean nothing
    closest = peer
    for entry in reversed(_forwarded_for(headers)):
        address = _valid_ip(entry)
        if address is None:
            # Our proxies write valid addresses, so this was written by the client: the
            # closest address to its right is the best we know.
            return closest
        if not _is_trusted(address, networks):
            return address
        closest = address
    return closest  # every hop is a proxy (for example a request from inside the platform)


def resolve_client_ip(
    peer: str | None,
    headers: Headers,
    *,
    proxy_hops: int = 0,
    trusted_networks: tuple[Network, ...] = (),
) -> str | None:
    """The client address, or the direct peer if nothing trustworthy says otherwise."""
    if trusted_networks:
        return _rightmost_untrusted(peer, headers, trusted_networks)
    if proxy_hops > 0:
        entries = _forwarded_for(headers)
        if len(entries) >= proxy_hops:
            found = _valid_ip(entries[-proxy_hops])
            if found:
                return found
    return peer
