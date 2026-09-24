"""Every kind of audit event CloudSentinel records."""

import enum


class AuditAction(enum.StrEnum):
    # Authentication
    LOGIN_SUCCEEDED = "LOGIN_SUCCEEDED"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGIN_RATE_LIMITED = "LOGIN_RATE_LIMITED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    LOGOUT = "LOGOUT"
    # FAILURE when the current password was wrong. (Event names, not secrets: S105.)
    PASSWORD_CHANGED = "PASSWORD_CHANGED"  # noqa: S105
    # A used refresh token was presented again: possible theft; all sessions revoked.
    REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"  # noqa: S105
    # Authorization
    ACCESS_DENIED = "ACCESS_DENIED"  # a signed-in user called a route their role forbids
    # Administration
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"  # role and/or active flag changed
    AWS_ACCOUNT_REGISTERED = "AWS_ACCOUNT_REGISTERED"
    AWS_ACCOUNT_VERIFIED = "AWS_ACCOUNT_VERIFIED"
    # Scanning and findings
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"  # COMPLETED or COMPLETED_WITH_ERRORS
    SCAN_FAILED = "SCAN_FAILED"
    FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"  # by an analyst (scan changes: see docs)


class AuditOutcome(enum.StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class TargetType(enum.StrEnum):
    USER = "USER"
    AWS_ACCOUNT = "AWS_ACCOUNT"
    SCAN = "SCAN"
    FINDING = "FINDING"
    ROUTE = "ROUTE"
