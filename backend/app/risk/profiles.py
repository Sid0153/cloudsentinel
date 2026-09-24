"""Per-rule risk profiles: exposure, impact and confidence decided from a finding's evidence.

Each profile reads only the finding's evidence and resource type, never AWS or the database,
so a stored finding can always be re-scored and gives the same result.
"""

from collections.abc import Callable
from typing import Any

from app.domain.resources import ResourceType
from app.risk.model import Confidence, Exposure, Impact, RiskFactors

Evidence = dict[str, Any]
Profile = Callable[[str, Evidence], RiskFactors]

UNSEEN_ATTACHMENTS = (
    "Attachments to load balancers, RDS and Lambda are not collected, so the group may be in use"
)
ALL_PORT_LABELS = {"all", "0-65535", "1-65535"}


def _security_group_exposure(evidence: Evidence) -> tuple[Exposure, str, Confidence, str]:
    if not evidence.get("attachments_known", False):
        return (
            Exposure.INTERNET,
            "Assumed reachable: the instances in this region could not be read",
            Confidence.MEDIUM,
            "Attachments unknown; the worst case was assumed",
        )
    if evidence.get("internet_facing_instance_ids"):
        count = len(evidence["internet_facing_instance_ids"])
        return (
            Exposure.INTERNET,
            f"Attached to {count} running instance(s) with a public IP address",
            Confidence.HIGH,
            "All inputs were available",
        )
    if evidence.get("attached_instance_ids"):
        return (
            Exposure.INDIRECT,
            "Attached only to instances without a public IP address",
            Confidence.HIGH,
            "All inputs were available",
        )
    return (
        Exposure.LATENT,
        "Not attached to any EC2 instance; exposed as soon as it is attached",
        Confidence.MEDIUM,
        UNSEEN_ATTACHMENTS,
    )


def remote_admin_port(resource_type: str, evidence: Evidence) -> RiskFactors:
    exposure, exposure_reason, confidence, confidence_reason = _security_group_exposure(evidence)
    return RiskFactors(
        exposure=exposure,
        exposure_reason=exposure_reason,
        impact=Impact.HIGH,
        impact_reason="Remote administration: a guessed or leaked credential gives a shell",
        confidence=confidence,
        confidence_reason=confidence_reason,
    )


def broad_inbound_access(resource_type: str, evidence: Evidence) -> RiskFactors:
    exposures = evidence.get("exposures", [])
    if any(e.get("ports") in ALL_PORT_LABELS for e in exposures):
        impact, impact_reason = Impact.SEVERE, "Every port is open, including any future service"
    elif any(e.get("sensitive_services") for e in exposures):
        services = sorted({s for e in exposures for s in e.get("sensitive_services", [])})
        impact = Impact.HIGH
        impact_reason = f"Sensitive services exposed: {', '.join(services[:5])}"
    else:
        impact, impact_reason = Impact.LIMITED, "Only non-sensitive ports are exposed"
    exposure, exposure_reason, confidence, confidence_reason = _security_group_exposure(evidence)
    return RiskFactors(
        exposure, exposure_reason, impact, impact_reason, confidence, confidence_reason
    )


def public_bucket(resource_type: str, evidence: Evidence) -> RiskFactors:
    if evidence.get("public_write"):
        impact, impact_reason = Impact.SEVERE, "Anyone can write to the bucket or change its ACL"
    else:
        impact, impact_reason = Impact.HIGH, "Anyone can read or list the bucket's data"
    return RiskFactors(
        Exposure.INTERNET, "The bucket is public", impact, impact_reason
    )


def bucket_not_encrypted(resource_type: str, evidence: Evidence) -> RiskFactors:
    return RiskFactors(
        Exposure.NONE,
        "Not an entry point by itself; matters once someone has storage access",
        Impact.LIMITED,
        "Defence in depth: data at rest is not encrypted by default",
    )


def console_user_without_mfa(resource_type: str, evidence: Evidence) -> RiskFactors:
    privileged = evidence.get("privileged")
    if privileged is None:
        return RiskFactors(
            Exposure.CONSOLE_LOGIN,
            "The AWS sign-in page is public and only a password protects this user",
            Impact.MODERATE,
            "The user's permissions could not be read",
            Confidence.MEDIUM,
            "Permissions unknown; a middle impact was assumed",
        )
    if privileged:
        impact, impact_reason = Impact.SEVERE, "The user has broad or administrator permissions"
    else:
        impact, impact_reason = Impact.MODERATE, "The user has limited permissions"
    return RiskFactors(
        Exposure.CONSOLE_LOGIN,
        "The AWS sign-in page is public and only a password protects this user",
        impact,
        impact_reason,
    )


def broad_permissions(resource_type: str, evidence: Evidence) -> RiskFactors:
    if evidence.get("full_admin"):
        impact, impact_reason = Impact.SEVERE, "Full administrator access to the account"
    else:
        impact, impact_reason = Impact.HIGH, "Every action of at least one service, on everything"

    confidence, confidence_reason = Confidence.HIGH, "All inputs were available"
    if any(s.get("has_condition") for s in evidence.get("broad_statements", [])):
        confidence = Confidence.MEDIUM
        confidence_reason = "Some statements have conditions, which are not evaluated"

    if resource_type == ResourceType.IAM_ROLE:
        exposure, exposure_reason = (
            Exposure.INDIRECT,
            "Used by whoever or whatever can assume the role (trust policy not analyzed)",
        )
    else:
        password = evidence.get("console_password")
        keys = evidence.get("active_access_keys")
        if password is None or keys is None:
            exposure, exposure_reason = Exposure.CREDENTIALS, "Assumed the user can sign in"
            confidence = Confidence.MEDIUM
            confidence_reason = "The credential report was unavailable"
        elif password or keys:
            exposure = Exposure.CREDENTIALS
            exposure_reason = "The user has a console password or active access keys"
        else:
            exposure = Exposure.LATENT
            exposure_reason = "The user has no password or active keys; nobody can sign in now"
    return RiskFactors(
        exposure, exposure_reason, impact, impact_reason, confidence, confidence_reason
    )


def cloudtrail_not_logging(resource_type: str, evidence: Evidence) -> RiskFactors:
    if evidence.get("some_single_region_trail_logging"):
        impact, impact_reason = Impact.LIMITED, "Some regions are recorded, others are not"
    else:
        impact, impact_reason = Impact.MODERATE, "No activity in the account is recorded"
    return RiskFactors(
        Exposure.NONE,
        "Not an entry point; it hides what an attacker does",
        impact,
        impact_reason,
    )


PROFILES: dict[str, Profile] = {
    "CS-SG-001": remote_admin_port,
    "CS-SG-002": remote_admin_port,
    "CS-SG-003": broad_inbound_access,
    "CS-S3-001": public_bucket,
    "CS-S3-002": bucket_not_encrypted,
    "CS-IAM-001": console_user_without_mfa,
    "CS-IAM-002": broad_permissions,
    "CS-CT-001": cloudtrail_not_logging,
}


def fallback(resource_type: str, evidence: Evidence) -> RiskFactors:
    """Used only if a rule has no profile (a test makes sure every shipped rule has one)."""
    return RiskFactors(
        Exposure.INDIRECT,
        "No risk profile for this rule; a middle value was used",
        Impact.MODERATE,
        "No risk profile for this rule; a middle value was used",
        Confidence.LOW,
        "No risk profile for this rule",
    )
