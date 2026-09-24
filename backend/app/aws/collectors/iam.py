"""IAM users and roles: the credential report (MFA, passwords, keys) and policy documents.

Only what the rules need is kept later. Trust policies, access key IDs and last-used
timestamps are not stored.
"""

import csv
import io
import time
from collections.abc import Callable
from typing import Any

from app.aws.common import (
    AWS_ERRORS,
    BOTO_CONFIG,
    GLOBAL_SERVICE_REGION,
    Boto3Session,
    Collected,
    error_label,
)
from app.aws.raw import RawIam

# Customer-managed policies are fetched with their documents. AWS-managed policies are
# not (there are over a thousand); only their ARNs are seen via the attachments.
AUTH_DETAILS_FILTER = ["User", "Role", "Group", "LocalManagedPolicy"]
_DETAIL_KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")

REPORT_POLL_SECONDS = 2.0
REPORT_MAX_POLLS = 15


class CredentialReportNotReadyError(Exception):
    pass


def read_credential_report(
    iam: Any, sleep: Callable[[float], None], max_polls: int = REPORT_MAX_POLLS
) -> list[dict[str, str]]:
    for attempt in range(max_polls):
        if iam.generate_credential_report().get("State") == "COMPLETE":
            break
        if attempt < max_polls - 1:
            sleep(REPORT_POLL_SECONDS)
    else:
        raise CredentialReportNotReadyError

    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def read_authorization_details(iam: Any) -> dict[str, list[dict[str, Any]]]:
    details: dict[str, list[dict[str, Any]]] = {key: [] for key in _DETAIL_KEYS}
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=AUTH_DETAILS_FILTER):
        for key in _DETAIL_KEYS:
            details[key].extend(page.get(key, []))
    return details


def collect_iam(
    session: Boto3Session, sleep: Callable[[float], None] = time.sleep
) -> Collected[RawIam]:
    result = Collected(raw=RawIam())
    iam = session.client("iam", region_name=GLOBAL_SERVICE_REGION, config=BOTO_CONFIG)

    try:
        result.raw.credential_report = read_credential_report(iam, sleep)
    except CredentialReportNotReadyError:
        result.errors.append("Credential report was not ready in time (GenerateCredentialReport)")
    except AWS_ERRORS as exc:
        result.errors.append(error_label("GetCredentialReport", exc))

    try:
        result.raw.authorization_details = read_authorization_details(iam)
    except AWS_ERRORS as exc:
        result.errors.append(error_label("GetAccountAuthorizationDetails", exc))

    details = result.raw.authorization_details
    if details is not None:
        result.items = len(details["UserDetailList"]) + len(details["RoleDetailList"])
    elif result.raw.credential_report is not None:
        result.items = len(result.raw.credential_report)
    return result
