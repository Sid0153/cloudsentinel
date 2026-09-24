"""Creates a small, deliberately mixed AWS environment inside moto."""

from dataclasses import dataclass
from typing import Any

import boto3

# moto does not load AWS-managed policies (such as AdministratorAccess) by default, so the
# seed uses a customer-managed policy with the same effect.
FULL_ACCESS_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
)


@dataclass
class Seeded:
    open_group_id: str
    instance_id: str
    trail_arn: str


def _any_image_id(ec2: Any) -> str:
    images = ec2.describe_images(Owners=["amazon"])["Images"]
    return str(images[0]["ImageId"]) if images else "ami-12c6146b"


def seed_environment() -> Seeded:
    """Must be called inside an active moto mock."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group_id = str(
        ec2.create_security_group(GroupName="ssh-open", Description="SSH from anywhere")["GroupId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    reservation = ec2.run_instances(
        ImageId=_any_image_id(ec2),
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SecurityGroupIds=[group_id],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "bastion"}]}
        ],
    )
    instance_id = str(reservation["Instances"][0]["InstanceId"])

    s3_east = boto3.client("s3", region_name="us-east-1")
    s3_east.create_bucket(Bucket="cs-public-bucket")
    s3_east.create_bucket(Bucket="cs-audit-logs")
    s3_west = boto3.client("s3", region_name="eu-west-1")
    s3_west.create_bucket(
        Bucket="cs-private-eu",
        CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
    )
    s3_west.put_bucket_encryption(
        Bucket="cs-private-eu",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    s3_west.put_public_access_block(
        Bucket="cs-private-eu",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Moto-only-password-1!")
    iam.put_user_policy(
        UserName="alice",
        PolicyName="star",
        PolicyDocument=(
            '{"Version":"2012-10-17",'
            '"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        ),
    )
    iam.create_user(UserName="readonly-bot")
    iam.create_role(
        RoleName="ops-admin",
        AssumeRolePolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        ),
    )
    policy_arn = iam.create_policy(
        PolicyName="ops-full-access", PolicyDocument=FULL_ACCESS_POLICY
    )["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="ops-admin", PolicyArn=policy_arn)

    cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")
    trail = cloudtrail.create_trail(
        Name="main-trail", S3BucketName="cs-audit-logs", IsMultiRegionTrail=True
    )
    cloudtrail.start_logging(Name="main-trail")

    return Seeded(open_group_id=group_id, instance_id=instance_id, trail_arn=str(trail["TrailARN"]))
