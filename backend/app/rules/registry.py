"""Every rule check CloudSentinel runs, listed explicitly (no import-time magic).

Adding a rule means: write the check, list it here, and add security-rules/rules/<id>.yaml.
The catalog loader refuses to start if a check and its metadata file do not match.
"""

from app.rules.checks import cloudtrail, iam, s3, security_groups
from app.rules.model import RuleCheck

ALL_CHECKS: list[RuleCheck] = [
    security_groups.unrestricted_ssh,
    security_groups.unrestricted_rdp,
    security_groups.broad_inbound_access,
    s3.public_bucket,
    s3.encryption_disabled,
    iam.console_user_without_mfa,
    iam.overly_broad_permissions,
    cloudtrail.no_multi_region_logging_trail,
]
