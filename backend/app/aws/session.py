"""Creating boto3 sessions. This code never reads, stores or logs credential values."""

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import boto3
from botocore.config import Config

from app.aws.common import BOTO_CONFIG, Boto3Session
from app.aws.raw import CallerIdentity
from app.core.config import get_settings

ASSUME_ROLE_SESSION_NAME = "CloudSentinel"
ASSUME_ROLE_SECONDS = 3600

# (role_arn or None, region) -> boto3 session. Injected so tests can simulate failures.
SessionBuilder = Callable[[str | None, str], Boto3Session]

# The simulator accepts any credentials. These fixed values mean the sandbox never looks at
# the real credential chain, so a real key can never be sent to the simulator.
SANDBOX_CREDENTIAL = "sandbox"
# Bucket names go in the path (http://simulator/bucket), not in the host name.
_SANDBOX_CLIENT_CONFIG = Config(s3={"addressing_style": "path"})
_AWS_ACCOUNT_ID_LENGTH = 12


def _drop_account_host_prefix(request: Any, **_kwargs: Any) -> None:
    """S3 Control puts the account ID in the host name (123456789012.<endpoint>).

    That works for real AWS but not for a simulator reached by a plain host name, so the
    prefix is removed before the request is signed and sent.
    """
    parts = urlsplit(request.url)
    prefix, dot, rest = parts.netloc.partition(".")
    if dot and prefix.isdigit() and len(prefix) == _AWS_ACCOUNT_ID_LENGTH:
        request.url = urlunsplit(parts._replace(netloc=rest))


class SandboxSession:
    """Looks like a boto3 session, but every client talks to the simulated AWS endpoint."""

    def __init__(
        self,
        endpoint: str,
        region: str,
        credentials: tuple[str, str, str | None] | None = None,
    ) -> None:
        key_id, secret, token = credentials or (SANDBOX_CREDENTIAL, SANDBOX_CREDENTIAL, None)
        self.endpoint = endpoint
        self._session = boto3.Session(
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            aws_session_token=token,
            region_name=region,
        )

    def client(self, service_name: str, **kwargs: Any) -> Any:
        config: Config | None = kwargs.pop("config", None)
        kwargs["config"] = (
            config.merge(_SANDBOX_CLIENT_CONFIG) if config else _SANDBOX_CLIENT_CONFIG
        )
        kwargs["endpoint_url"] = self.endpoint
        client = self._session.client(service_name, **kwargs)
        if service_name == "s3control":
            client.meta.events.register("before-sign.s3-control", _drop_account_host_prefix)
        return client


def build_session(role_arn: str | None, region: str) -> Boto3Session:
    """A boto3 session from the standard credential chain (env vars, profile, SSO, ...).

    With role_arn, that identity assumes the role and the session uses the temporary
    credentials. Nothing is written to disk or the database. In sandbox mode the session
    talks to the simulated AWS instead (see docs/sandbox.md).
    """
    endpoint = get_settings().sandbox_aws_endpoint
    base: Boto3Session = (
        boto3.Session(region_name=region) if endpoint is None else SandboxSession(endpoint, region)
    )
    if role_arn is None:
        return base

    response = base.client("sts", config=BOTO_CONFIG).assume_role(
        RoleArn=role_arn,
        RoleSessionName=ASSUME_ROLE_SESSION_NAME,
        DurationSeconds=ASSUME_ROLE_SECONDS,
    )
    credentials = response["Credentials"]
    if endpoint is not None:
        return SandboxSession(
            endpoint,
            region,
            (
                credentials["AccessKeyId"],
                credentials["SecretAccessKey"],
                credentials["SessionToken"],
            ),
        )
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
