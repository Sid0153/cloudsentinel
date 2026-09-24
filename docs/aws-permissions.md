# AWS permissions

CloudSentinel is **read-only**. It never creates, changes or deletes anything in AWS, and it
never stores AWS credentials. Give it a dedicated identity with only the permissions below.
Do not use `AdministratorAccess`, and do not use the account root user.

## The policy

The policy is in [`infrastructure/cloudsentinel-readonly-policy.json`](../infrastructure/cloudsentinel-readonly-policy.json).

| API call | IAM action | Why |
|---|---|---|
| `sts:GetCallerIdentity` | none needed | Confirms which account the credentials belong to |
| `ec2:DescribeInstances` | `ec2:DescribeInstances` | Instances, state, IPs, attached security groups |
| `ec2:DescribeSecurityGroups` | `ec2:DescribeSecurityGroups` | Inbound and outbound rules |
| `s3:ListBuckets` | `s3:ListAllMyBuckets` | Bucket inventory |
| `s3:GetBucketLocation` | `s3:GetBucketLocation` | Bucket region |
| `s3:GetBucketEncryption` | `s3:GetEncryptionConfiguration` | Default encryption |
| `s3:GetPublicAccessBlock` (bucket) | `s3:GetBucketPublicAccessBlock` | Bucket-level Block Public Access |
| `s3control:GetPublicAccessBlock` | `s3:GetAccountPublicAccessBlock` | Account-level Block Public Access |
| `s3:GetBucketPolicyStatus` | `s3:GetBucketPolicyStatus` | AWS's own verdict on whether the bucket policy is public |
| `s3:GetBucketAcl` | `s3:GetBucketAcl` | Public ACL grants |
| `iam:GenerateCredentialReport` | `iam:GenerateCredentialReport` | Starts the credential report |
| `iam:GetCredentialReport` | `iam:GetCredentialReport` | Console password, MFA and access-key status per user |
| `iam:GetAccountAuthorizationDetails` | `iam:GetAccountAuthorizationDetails` | Users, groups, roles and customer-managed policy documents |
| `cloudtrail:DescribeTrails` | `cloudtrail:DescribeTrails` | Trail configuration |
| `cloudtrail:GetTrailStatus` | `cloudtrail:GetTrailStatus` | Whether each trail is logging |

Sources: the S3 API reference pages for each operation, the S3 Block Public Access
permissions table, and the IAM credential report guide.

### Why not the AWS-managed `SecurityAudit` or `ReadOnlyAccess` policies?

They work, but grant read access to hundreds of other APIs. `ReadOnlyAccess` can even read
data (for example S3 objects). The custom policy above is the least privilege for what
CloudSentinel actually does, and it cannot read object contents.

### What the collected data contains

- **Stored:** resource IDs, names, network rules, bucket settings, per-user flags (console
  password enabled, MFA active, access keys active), the ARNs of attached policies, and the
  individual wildcard statements that make a policy "broad".
- **Not stored:** the root account's credential report row, access key IDs, last-used dates,
  role trust policies, full policy documents, object data, or any credential.

## If a permission is missing

The scan still runs. Each service's result is recorded in the scan's `coverage` as
`SUCCEEDED`, `PARTIAL` or `FAILED`, with short error labels such as
`AccessDenied (GetBucketAcl)`, and the scan ends as `COMPLETED_WITH_ERRORS`. A missing
permission therefore shows up as "could not check", never as "no problem found".

## Setting up credentials (recommended order)

CloudSentinel uses boto3's standard credential chain, so no code or config file in this
repository ever holds a key.

1. **IAM Identity Center (SSO) profile.** Short-lived credentials, nothing long-lived on disk.
   Create a permission set from the policy above, then `aws configure sso` and
   `aws sso login --profile cloudsentinel`.
2. **Assume a role.** Create a role with the policy above, trusted by the identity the
   backend runs as, and set the role ARN when registering the AWS account in CloudSentinel.
   The backend calls `sts:AssumeRole` (the calling identity needs that permission) and uses
   one-hour temporary credentials.
3. **Dedicated IAM user with an access key** (simplest for a personal lab). Attach only the
   policy above, store the key in a named profile with `aws configure --profile cloudsentinel`
   (it goes to `~/.aws/credentials`), rotate it regularly and delete it when you are done.

Never paste keys into `.env`, source code, the CloudSentinel UI, issues or chat.

## Running a real scan

**Backend on your machine (simplest):**

```bash
cd backend
export AWS_PROFILE=cloudsentinel          # PowerShell: $env:AWS_PROFILE="cloudsentinel"
uvicorn app.main:create_app --factory
```

**Backend in Docker:** the default stack has no AWS access. Add the override file, which
mounts your AWS config folder read-only and selects a profile:

```bash
# in .env: AWS_PROFILE=cloudsentinel and AWS_CONFIG_DIR=/home/you/.aws (C:/Users/you/.aws on Windows)
docker compose -f docker-compose.yml -f docker-compose.aws.yml up --build
```

The folder is mounted read-only. For an SSO profile, run `aws sso login --profile ...` on
your machine first; the container can read the cached token but cannot refresh it.

Then, as an ADMIN, register the account (`POST /api/aws-accounts`), check it
(`POST /api/aws-accounts/{id}/verify` should return `"matches": true`), and start a scan as an
ANALYST or ADMIN (`POST /api/scans`).

## Cost and safety

The calls above are free API reads. Scanning an empty or small account costs nothing. Set up
an AWS Budget alert on any personal account anyway.
