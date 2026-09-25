"""Which address a request came from, for the rate limits and the audit log.

Proxies append to X-Forwarded-For, so its left part is whatever the client chose to send and
can be anything. Only the entries added by our own proxies can be trusted, which means
reading from the right: with N trusted proxies in front of the app, the N-th entry from the
right was written by the outermost of them and is the address it saw.

Some platforms instead put the client address in a header they always overwrite (Render,
behind Cloudflare: True-Client-IP). CLIENT_IP_HEADER names that header.

Without either setting, the direct peer address is used and X-Forwarded-For is ignored.
"""

import ipaddress

from starlette.datastructures import Headers


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def resolve_client_ip(
    peer: str | None, headers: Headers, *, header: str | None, proxy_hops: int
) -> str | None:
    """The client address, or the direct peer if the configured source is missing or invalid."""
    if header:
        value = headers.get(header)
        found = _valid_ip(value.split(",")[0]) if value else None
        return found or peer
    if proxy_hops > 0:
        entries = [
            entry.strip()
            for line in headers.getlist("x-forwarded-for")
            for entry in line.split(",")
            if entry.strip()
        ]
        if len(entries) >= proxy_hops:
            found = _valid_ip(entries[-proxy_hops])
            if found:
                return found
    return peer
