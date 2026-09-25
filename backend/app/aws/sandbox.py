"""The sandbox: a small AWS environment inside the simulator, and switches that change it.

Only used in sandbox mode, where every session is a SandboxSession pointing at the simulator
(moto), so none of these write calls can reach a real AWS account. The API only builds these
sessions when SANDBOX_AWS_ENDPOINT is set (app/api/sandbox.py). This module is also the only
code that changes anything in "AWS"; the scanner itself stays read-only.

The simulator keeps everything in memory. When it restarts it is empty, so
ensure_environment() recreates the environment before it is shown or scanned.
"""

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.aws.common import AWS_ERRORS, BOTO_CONFIG, Boto3Session, error_code

SANDBOX_ACCOUNT_ID = "123456789012"  # moto's fixed account ID
SANDBOX_REGION = "us-east-1"

BASTION_GROUP = "sandbox-bastion"
DATABASE_GROUP = "sandbox-database"
WEBSITE_BUCKET = "sandbox-website-assets"
DATA_BUCKET = "sandbox-customer-data"
LOG_BUCKET = "sandbox-cloudtrail-logs"
CONSOLE_USER = "sandbox-developer"
DEPLOY_USER = "sandbox-deploy-bot"
DEPLOY_POLICY = "deploy"
TRAIL = "sandbox-trail"  # created last: its presence means the environment is complete

_ANYWHERE = "0.0.0.0/0"
_BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
_AES256 = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
# moto accepts any MFA codes.
_MFA_CODES = ("123456", "654321")


@dataclass
class Clients:
    ec2: Any
    s3: Any
    iam: Any
    cloudtrail: Any


def clients_for(session: Boto3Session) -> Clients:
    def make(service: str) -> Any:
        return session.client(service, region_name=SANDBOX_REGION, config=BOTO_CONFIG)

    return Clients(make("ec2"), make("s3"), make("iam"), make("cloudtrail"))


def _policy(actions: str | list[str], resource: str) -> str:
    statement = {"Effect": "Allow", "Action": actions, "Resource": resource}
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


# --- Security groups ----------------------------------------------------------------------


def _group_id(clients: Clients, name: str) -> str:
    groups = clients.ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [name]}]
    )["SecurityGroups"]
    return str(groups[0]["GroupId"])


def _port_permission(port: int) -> dict[str, Any]:
    return {
        "IpProtocol": "tcp",
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": _ANYWHERE}],
    }


def _port_open(group: str, port: int) -> Callable[[Clients], bool]:
    def read(clients: Clients) -> bool:
        groups = clients.ec2.describe_security_groups(GroupIds=[_group_id(clients, group)])
        return any(
            permission.get("FromPort") == port
            and any(r.get("CidrIp") == _ANYWHERE for r in permission.get("IpRanges", []))
            for permission in groups["SecurityGroups"][0].get("IpPermissions", [])
        )

    return read


def _set_port_open(group: str, port: int) -> Callable[[Clients, bool], None]:
    def write(clients: Clients, insecure: bool) -> None:
        if _port_open(group, port)(clients) == insecure:
            return
        change = (
            clients.ec2.authorize_security_group_ingress
            if insecure
            else clients.ec2.revoke_security_group_ingress
        )
        change(GroupId=_group_id(clients, group), IpPermissions=[_port_permission(port)])

    return write


# --- S3 -----------------------------------------------------------------------------------


def _website_public(clients: Clients) -> bool:
    grants = clients.s3.get_bucket_acl(Bucket=WEBSITE_BUCKET)["Grants"]
    return any("AllUsers" in str(grant["Grantee"].get("URI", "")) for grant in grants)


def _set_website_public(clients: Clients, insecure: bool) -> None:
    if insecure:
        clients.s3.delete_public_access_block(Bucket=WEBSITE_BUCKET)
        clients.s3.put_bucket_acl(Bucket=WEBSITE_BUCKET, ACL="public-read")
    else:
        clients.s3.put_bucket_acl(Bucket=WEBSITE_BUCKET, ACL="private")
        clients.s3.put_public_access_block(
            Bucket=WEBSITE_BUCKET, PublicAccessBlockConfiguration=_BLOCK_ALL
        )


def _data_unencrypted(clients: Clients) -> bool:
    try:
        clients.s3.get_bucket_encryption(Bucket=DATA_BUCKET)
    except AWS_ERRORS as exc:
        if error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
            return True
        raise
    return False


def _set_data_unencrypted(clients: Clients, insecure: bool) -> None:
    if insecure:
        clients.s3.delete_bucket_encryption(Bucket=DATA_BUCKET)
    else:
        clients.s3.put_bucket_encryption(
            Bucket=DATA_BUCKET, ServerSideEncryptionConfiguration=_AES256
        )


# --- IAM ----------------------------------------------------------------------------------


def _console_user_without_mfa(clients: Clients) -> bool:
    return not clients.iam.list_mfa_devices(UserName=CONSOLE_USER)["MFADevices"]


def _set_console_user_without_mfa(clients: Clients, insecure: bool) -> None:
    devices = clients.iam.list_mfa_devices(UserName=CONSOLE_USER)["MFADevices"]
    if insecure:
        for device in devices:
            serial = device["SerialNumber"]
            clients.iam.deactivate_mfa_device(UserName=CONSOLE_USER, SerialNumber=serial)
            clients.iam.delete_virtual_mfa_device(SerialNumber=serial)
    elif not devices:
        device = clients.iam.create_virtual_mfa_device(VirtualMFADeviceName=CONSOLE_USER)
        clients.iam.enable_mfa_device(
            UserName=CONSOLE_USER,
            SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
            AuthenticationCode1=_MFA_CODES[0],
            AuthenticationCode2=_MFA_CODES[1],
        )


def _deploy_user_is_admin(clients: Clients) -> bool:
    document = clients.iam.get_user_policy(UserName=DEPLOY_USER, PolicyName=DEPLOY_POLICY)
    policy = document["PolicyDocument"]
    if isinstance(policy, str):
        policy = json.loads(policy)
    return any(statement.get("Action") == "*" for statement in policy["Statement"])


def _set_deploy_user_is_admin(clients: Clients, insecure: bool) -> None:
    document = (
        _policy("*", "*")
        if insecure
        else _policy("s3:PutObject", f"arn:aws:s3:::{WEBSITE_BUCKET}/*")
    )
    clients.iam.put_user_policy(
        UserName=DEPLOY_USER, PolicyName=DEPLOY_POLICY, PolicyDocument=document
    )


# --- CloudTrail ---------------------------------------------------------------------------


def _trail_stopped(clients: Clients) -> bool:
    return not clients.cloudtrail.get_trail_status(Name=TRAIL)["IsLogging"]


def _set_trail_stopped(clients: Clients, insecure: bool) -> None:
    if insecure:
        clients.cloudtrail.stop_logging(Name=TRAIL)
    else:
        clients.cloudtrail.start_logging(Name=TRAIL)


# --- The switches -------------------------------------------------------------------------


@dataclass(frozen=True)
class Control:
    """One switch. "insecure" means the setting a security rule should flag."""

    key: str
    title: str
    description: str
    rule_id: str
    insecure_by_default: bool
    is_insecure: Callable[[Clients], bool]
    set_insecure: Callable[[Clients, bool], None]


CONTROLS: tuple[Control, ...] = (
    Control(
        "ssh-open",
        "SSH open to the internet",
        f"Security group {BASTION_GROUP} (attached to the bastion instance) allows port 22 "
        "from anywhere.",
        "CS-SG-001",
        True,
        _port_open(BASTION_GROUP, 22),
        _set_port_open(BASTION_GROUP, 22),
    ),
    Control(
        "rdp-open",
        "Remote Desktop open to the internet",
        f"Security group {BASTION_GROUP} allows port 3389 from anywhere.",
        "CS-SG-002",
        False,
        _port_open(BASTION_GROUP, 3389),
        _set_port_open(BASTION_GROUP, 3389),
    ),
    Control(
        "database-open",
        "Database port open to the internet",
        f"Security group {DATABASE_GROUP} allows PostgreSQL (port 5432) from anywhere.",
        "CS-SG-003",
        False,
        _port_open(DATABASE_GROUP, 5432),
        _set_port_open(DATABASE_GROUP, 5432),
    ),
    Control(
        "bucket-public",
        "Bucket readable by anyone",
        f"Bucket {WEBSITE_BUCKET} has a public-read ACL and no Block Public Access.",
        "CS-S3-001",
        True,
        _website_public,
        _set_website_public,
    ),
    Control(
        "bucket-unencrypted",
        "Bucket without default encryption",
        f"Bucket {DATA_BUCKET} has no default encryption configured.",
        "CS-S3-002",
        False,
        _data_unencrypted,
        _set_data_unencrypted,
    ),
    Control(
        "console-user-no-mfa",
        "Console user without MFA",
        f"IAM user {CONSOLE_USER} can sign in to the console with only a password.",
        "CS-IAM-001",
        True,
        _console_user_without_mfa,
        _set_console_user_without_mfa,
    ),
    Control(
        "deploy-bot-admin",
        "Automation user with full admin rights",
        f"IAM user {DEPLOY_USER} has an inline policy allowing every action on every resource "
        "(instead of only uploading to the website bucket).",
        "CS-IAM-002",
        False,
        _deploy_user_is_admin,
        _set_deploy_user_is_admin,
    ),
    Control(
        "cloudtrail-off",
        "Activity logging switched off",
        f"The multi-region CloudTrail trail {TRAIL} is not logging.",
        "CS-CT-001",
        True,
        _trail_stopped,
        _set_trail_stopped,
    ),
)
CONTROLS_BY_KEY = {control.key: control for control in CONTROLS}


# --- Building the environment -------------------------------------------------------------


def _image_id(clients: Clients) -> str:
    images = clients.ec2.describe_images(Owners=["amazon"])["Images"]
    return str(images[0]["ImageId"]) if images else "ami-12c6146b"


def _create_environment(clients: Clients) -> None:
    ec2 = clients.ec2
    bastion = ec2.create_security_group(GroupName=BASTION_GROUP, Description="Bastion host")
    ec2.create_security_group(GroupName=DATABASE_GROUP, Description="Customer database")
    ec2.run_instances(
        ImageId=_image_id(clients),
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SecurityGroupIds=[bastion["GroupId"]],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "bastion"}]}
        ],
    )

    for bucket in (WEBSITE_BUCKET, DATA_BUCKET, LOG_BUCKET):
        clients.s3.create_bucket(Bucket=bucket)
        clients.s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration=_AES256)
        clients.s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=_BLOCK_ALL)

    iam = clients.iam
    iam.create_user(UserName=CONSOLE_USER)
    # A random password nobody knows: only the existence of a console login matters here.
    iam.create_login_profile(UserName=CONSOLE_USER, Password=secrets.token_urlsafe(24) + "aA1!")
    iam.put_user_policy(
        UserName=CONSOLE_USER,
        PolicyName="read-website",
        PolicyDocument=_policy(
            ["s3:GetObject", "s3:ListBucket"], f"arn:aws:s3:::{WEBSITE_BUCKET}*"
        ),
    )
    iam.create_user(UserName=DEPLOY_USER)
    _set_deploy_user_is_admin(clients, False)

    clients.cloudtrail.create_trail(Name=TRAIL, S3BucketName=LOG_BUCKET, IsMultiRegionTrail=True)
    clients.cloudtrail.start_logging(Name=TRAIL)


def _environment_exists(clients: Clients) -> bool:
    trails = clients.cloudtrail.describe_trails(trailNameList=[TRAIL])["trailList"]
    return any(trail.get("Name") == TRAIL for trail in trails)


def apply_defaults(clients: Clients) -> None:
    for control in CONTROLS:
        control.set_insecure(clients, control.insecure_by_default)


def ensure_environment(clients: Clients) -> bool:
    """Creates the environment if the simulator is empty. Returns True if it was created."""
    if _environment_exists(clients):
        return False
    _create_environment(clients)
    apply_defaults(clients)
    return True


def read_states(clients: Clients) -> dict[str, bool]:
    """Current state of every switch: key -> insecure."""
    return {control.key: control.is_insecure(clients) for control in CONTROLS}
