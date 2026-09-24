"""Creating boto3 sessions. This code never reads, stores or logs credential values."""

from collections.abc import Callable

import boto3

from app.aws.common import BOTO_CONFIG, Boto3Session
from app.aws.raw import CallerIdentity

ASSUME_ROLE_SESSION_NAME = "CloudSentinel"
ASSUME_ROLE_SECONDS = 3600

# (role_arn or None, region) -> boto3 session. Injected so tests can simulate failures.
SessionBuilder = Callable[[str | None, str], Boto3Session]


def build_session(role_arn: str | None, region: str) -> Boto3Session:
    """A boto3 session from the standard credential chain (env vars, profile, SSO, ...).

    With role_arn, that identity assumes the role and the session uses the temporary
    credentials. Nothing is written to disk or the database.
    """
    base = boto3.Session(region_name=region)
    if role_arn is None:
        return base

    response = base.client("sts", config=BOTO_CONFIG).assume_role(
        RoleArn=role_arn,
        RoleSessionName=ASSUME_ROLE_SESSION_NAME,
        DurationSeconds=ASSUME_ROLE_SECONDS,
    )
    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def get_caller_identity(session: Boto3Session) -> CallerIdentity:
    """STS GetCallerIdentity needs no IAM permission, so it works for any valid credentials."""
    response = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
    return CallerIdentity(account_id=str(response["Account"]), arn=str(response["Arn"]))
