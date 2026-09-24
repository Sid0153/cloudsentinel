"""Hand-written AWS API responses: secure, vulnerable and edge-case configurations.

Shapes follow the boto3 responses for each API. They let the normalizers be tested without
any AWS calls or mocks.
"""

from typing import Any

REGION = "us-east-1"

OPEN_SSH_GROUP: dict[str, Any] = {
    "GroupId": "sg-open",
    "GroupName": "web-admin",
    "Description": "SSH from anywhere",
    "VpcId": "vpc-1",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            "UserIdGroupPairs": [],
            "PrefixListIds": [],
        }
    ],
    "IpPermissionsEgress": [
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ],
}

PRIVATE_GROUP: dict[str, Any] = {
    "GroupId": "sg-private",
    "GroupName": "db",
    "Description": "Postgres from the app tier only",
    "VpcId": "vpc-1",
    "IpPermissions": [
        {
            "IpProtocol": "6",  # numeric protocol value, as EC2 may report it
            "FromPort": 5432,
            "ToPort": 5432,
            "UserIdGroupPairs": [{"GroupId": "sg-open"}],
            "PrefixListIds": [{"PrefixListId": "pl-123"}],
        }
    ],
    "IpPermissionsEgress": [],
}

RUNNING_INSTANCE: dict[str, Any] = {
    "InstanceId": "i-running",
    "State": {"Name": "running"},
    "InstanceType": "t3.micro",
    "PublicIpAddress": "203.0.113.10",
    "PrivateIpAddress": "10.0.0.10",
    "VpcId": "vpc-1",
    "SubnetId": "subnet-1",
    "SecurityGroups": [{"GroupId": "sg-open", "GroupName": "web-admin"}],
    "Tags": [{"Key": "Name", "Value": "bastion"}, {"Key": "env", "Value": "dev"}],
}

TERMINATED_INSTANCE: dict[str, Any] = {
    "InstanceId": "i-gone",
    "State": {"Name": "terminated"},
    "SecurityGroups": [{"GroupId": "sg-private"}],
}

ENCRYPTION_RULES_KMS: list[dict[str, Any]] = [
    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}
]

FULL_BLOCK: dict[str, Any] = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

PUBLIC_READ_GRANTS: list[dict[str, Any]] = [
    {"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"},
    {
        "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
        "Permission": "READ",
    },
]

CREDENTIAL_REPORT: list[dict[str, str]] = [
    {
        "user": "<root_account>",
        "arn": "arn:aws:iam::123456789012:root",
        "password_enabled": "not_supported",
        "mfa_active": "true",
        "access_key_1_active": "false",
        "access_key_2_active": "false",
    },
    {
        "user": "alice",
        "arn": "arn:aws:iam::123456789012:user/alice",
        "password_enabled": "true",
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_2_active": "false",
    },
    {
        "user": "ci-bot",
        "arn": "arn:aws:iam::123456789012:user/ci-bot",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_2_active": "N/A",
    },
]

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
LOCAL_POLICY_ARN = "arn:aws:iam::123456789012:policy/everything-s3"

AUTHORIZATION_DETAILS: dict[str, list[dict[str, Any]]] = {
    "UserDetailList": [
        {
            "UserName": "alice",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "GroupList": ["admins"],
            "UserPolicyList": [
                {
                    "PolicyName": "star",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        },
        {
            "UserName": "ci-bot",
            "Arn": "arn:aws:iam::123456789012:user/ci-bot",
            "GroupList": [],
            "UserPolicyList": [
                {
                    "PolicyName": "scoped",
                    # URL-encoded JSON string, the raw API form
                    "PolicyDocument": (
                        "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22"
                        "%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22arn%3Aaws%3As3%3A%3A%3A"
                        "builds%2F%2A%22%7D%5D%7D"
                    ),
                }
            ],
            "AttachedManagedPolicies": [
                {"PolicyName": "everything-s3", "PolicyArn": LOCAL_POLICY_ARN}
            ],
        },
    ],
    "GroupDetailList": [
        {
            "GroupName": "admins",
            "GroupPolicyList": [],
            "AttachedManagedPolicies": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}
            ],
        }
    ],
    "RoleDetailList": [
        {
            "RoleName": "deployer",
            "Arn": "arn:aws:iam::123456789012:role/deployer",
            "Path": "/",
            "RolePolicyList": [
                {
                    "PolicyName": "conditional-ec2",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["ec2:*", "s3:GetObject"],
                                "Resource": "*",
                                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                            },
                            {"Effect": "Deny", "Action": "*", "Resource": "*"},
                        ]
                    },
                }
            ],
            "AttachedManagedPolicies": [],
            "AssumeRolePolicyDocument": {"Statement": []},
        }
    ],
    "Policies": [
        {
            "PolicyName": "everything-s3",
            "Arn": LOCAL_POLICY_ARN,
            "PolicyVersionList": [
                {
                    "IsDefaultVersion": False,
                    "Document": {
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    },
                },
                {
                    "IsDefaultVersion": True,
                    "Document": {
                        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
                    },
                },
            ],
        }
    ],
}

MULTI_REGION_TRAIL: dict[str, Any] = {
    "Name": "org-audit",
    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit",
    "HomeRegion": "us-east-1",
    "IsMultiRegionTrail": True,
    "IsOrganizationTrail": False,
    "LogFileValidationEnabled": True,
    "S3BucketName": "audit-logs",
}
