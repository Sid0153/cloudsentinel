"""docs/database-schema.md must describe every table and column the models define."""

import re
from pathlib import Path

import app.models  # noqa: F401  (registers the tables on Base.metadata)
from app.database.base import Base

SCHEMA_MD = Path(__file__).resolve().parents[3] / "docs" / "database-schema.md"


def _documented() -> dict[str, set[str]]:
    """Table name -> column names, from the '## table' sections and their `column` rows."""
    tables: dict[str, set[str]] = {}
    current: str | None = None
    for line in SCHEMA_MD.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^## (\w+)$", line)
        if heading:
            current = heading.group(1)
            tables[current] = set()
            continue
        row = re.match(r"^\| `(\w+)` \|", line)
        if row and current is not None:
            tables[current].add(row.group(1))
    return tables


def test_every_table_and_column_is_documented() -> None:
    documented = _documented()
    for table in Base.metadata.sorted_tables:
        assert table.name in documented, f"table {table.name} missing from docs/database-schema.md"
        columns = {column.name for column in table.columns}
        assert documented[table.name] == columns, f"columns of {table.name} differ from the docs"
