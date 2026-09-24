"""The rule catalog used by the application, loaded once from the configured directory."""

from functools import lru_cache

from app.core.config import get_settings
from app.rules.catalog import RuleCatalog, load_catalog
from app.rules.registry import ALL_CHECKS


@lru_cache
def get_rule_catalog() -> RuleCatalog:
    return load_catalog(get_settings().rules_dir, ALL_CHECKS)
