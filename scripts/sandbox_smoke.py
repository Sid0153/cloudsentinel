"""End-to-end check of sandbox mode against the running Docker Compose stack.

    docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up -d --build --wait
    python scripts/sandbox_smoke.py [http://localhost:8080]

Signs in as the guest, scans the simulated AWS, changes two switches, scans again and checks
that exactly the expected findings opened and closed. Uses only the standard library, so it
runs on a CI runner without installing anything. Exits non-zero on the first failed check.
"""

import json
import sys
import time
import urllib.request
from typing import Any

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
SANDBOX_ACCOUNT_ID = "123456789012"
SCAN_TIMEOUT_SECONDS = 180


def call(method: str, path: str, token: str | None = None, body: Any = None) -> Any:
    request = urllib.request.Request(f"{BASE}/api{path}", method=method)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, data=data, timeout=30) as response:  # noqa: S310
        return json.loads(response.read() or "null")


def check(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}")
        sys.exit(1)
    print(f"ok: {message}")


def scan(token: str, account: str) -> dict[str, Any]:
    started = call("POST", "/scans", token, {"aws_account_id": account})
    deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        current: dict[str, Any] = call("GET", f"/scans/{started['id']}", token)
        if current["status"] not in ("PENDING", "RUNNING"):
            return current
        time.sleep(2)
    check(False, f"scan finished within {SCAN_TIMEOUT_SECONDS} s")
    return {}


def open_rules(token: str) -> set[str]:
    findings = call("GET", "/findings?status=OPEN&limit=500", token)
    return {finding["rule_id"] for finding in findings}


def main() -> None:
    about = call("GET", "/about")
    check(about["sandbox_mode"] and about["guest_access"], "sandbox mode and guest access on")

    session = call("POST", "/auth/guest")
    token = session["access_token"]
    check(session["user"]["role"] == "ANALYST", "guest signed in as ANALYST")

    accounts = call("GET", "/aws-accounts", token)
    matching = [a["id"] for a in accounts if a["account_id"] == SANDBOX_ACCOUNT_ID]
    check(len(matching) == 1, "the simulated AWS account is registered")
    account = matching[0]

    state = call("POST", "/sandbox/reset", token)
    defaults = {c["rule_id"] for c in state["controls"] if c["insecure_by_default"]}
    check(len(state["controls"]) == 8, "the sandbox has 8 switches")

    first = scan(token, account)
    check(first["status"] == "COMPLETED", f"first scan COMPLETED (got {first['status']})")
    check(open_rules(token) == defaults, f"open findings match the defaults {sorted(defaults)}")

    call("PATCH", "/sandbox/controls/ssh-open", token, {"insecure": False})
    call("PATCH", "/sandbox/controls/rdp-open", token, {"insecure": True})
    second = scan(token, account)
    check(second["status"] == "COMPLETED", f"second scan COMPLETED (got {second['status']})")
    expected = (defaults - {"CS-SG-001"}) | {"CS-SG-002"}
    check(open_rules(token) == expected, "SSH finding closed, RDP finding opened")

    call("POST", "/sandbox/reset", token)
    print("Sandbox smoke test passed")


if __name__ == "__main__":
    main()
