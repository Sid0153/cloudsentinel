"""Shared helpers for talking to AWS with boto3."""

from dataclasses import dataclass, field
from typing import Any

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# A boto3.Session. boto3 ships no type information, so it is typed as Any.
Boto3Session = Any

# Errors that mean "AWS said no" or "we could not talk to AWS". Anything else is a bug.
AWS_ERRORS = (BotoCoreError, ClientError)

# IAM, S3 bucket listing and account-level S3 settings are global; this region is used for them.
GLOBAL_SERVICE_REGION = "us-east-1"

BOTO_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 5},  # backs off when AWS throttles us
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra="CloudSentinel/0.1",
)


@dataclass
class Collected[T]:
    """What a collector returns: the raw data, what could not be read, and an item count."""

    raw: T
    errors: list[str] = field(default_factory=list)
    items: int = 0


def error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", "Unknown"))
    return type(exc).__name__


def error_label(operation: str, exc: BaseException) -> str:
    """Short, safe description: AWS error code and operation only.

    The full AWS message can contain account IDs, ARNs or policy details, so it is left out.
    """
    return f"{error_code(exc)} ({operation})"
