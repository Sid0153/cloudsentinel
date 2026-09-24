import hashlib

from app.domain.resources import ResourceKey


def fingerprint(aws_account_id: str, rule_id: str, key: ResourceKey) -> str:
    """A stable identity for "this rule failing on this resource".

    Built from the 12-digit AWS account ID (not an internal database ID), so it stays the same
    if the account is removed and registered again. Evidence and severity are deliberately
    left out: they may change between scans while the problem is still the same one.
    """
    region, resource_type, resource_id = key
    identity = "|".join((aws_account_id, rule_id, resource_type, region, resource_id))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()
