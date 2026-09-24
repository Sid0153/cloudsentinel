"""The API documentation in docs/ must match the code."""

import json
import re
from pathlib import Path

from app.cli import OPENAPI_PATH, openapi_document
from tests.api.test_rbac import EXPECTED_ACCESS, PUBLIC_ROUTES

API_MD = Path(__file__).resolve().parents[3] / "docs" / "api.md"
ROLE_TEXT = {None: "any signed-in user", "ADMIN": "ADMIN", "ANALYST": "ANALYST"}


def test_committed_openapi_matches_the_code() -> None:
    committed = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    current = json.loads(openapi_document())
    assert committed == current, "docs/openapi.json is stale: run python -m app.cli export-openapi"


def _rows() -> dict[str, str]:
    """`METHOD /path` -> role column, from the endpoint table in docs/api.md."""
    rows: dict[str, str] = {}
    for line in API_MD.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `([A-Z]+ /api/\S+)` \| ([^|]+) \|", line)
        if match:
            rows[match.group(1)] = match.group(2).strip()
    return rows


def test_every_route_is_documented_with_the_role_it_really_needs() -> None:
    rows = _rows()
    for (method, path), minimum in EXPECTED_ACCESS.items():
        role = None if minimum is None else str(minimum)
        assert rows.get(f"{method} {path}") == ROLE_TEXT[role], f"{method} {path} in docs/api.md"
    for method, path in PUBLIC_ROUTES:
        assert rows.get(f"{method} {path}", "").startswith("public"), f"{method} {path}"
    documented = set(rows)
    real = {f"{m} {p}" for m, p in EXPECTED_ACCESS} | {f"{m} {p}" for m, p in PUBLIC_ROUTES}
    assert documented == real, "docs/api.md lists a route that does not exist"
