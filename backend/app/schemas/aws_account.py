import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Standard commercial and GovCloud regions such as us-east-1, ap-southeast-2, us-gov-west-1.
_REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d{1,2}$")
_ROLE_ARN = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
MAX_REGIONS = 20


class AwsAccountCreate(BaseModel):
    account_id: str = Field(pattern=r"^\d{12}$", description="12-digit AWS account ID")
    name: str = Field(min_length=1, max_length=100)
    regions: list[str] = Field(min_length=1, max_length=MAX_REGIONS)
    role_arn: str | None = Field(default=None, max_length=2048)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Name must not be blank")
        return stripped

    @field_validator("regions")
    @classmethod
    def _valid_regions(cls, value: list[str]) -> list[str]:
        regions: list[str] = []
        for region in value:
            region = region.strip().lower()
            if not _REGION.match(region):
                raise ValueError(f"Not a valid AWS region name: {region[:30]}")
            if region not in regions:
                regions.append(region)
        return regions

    @field_validator("role_arn")
    @classmethod
    def _valid_role_arn(cls, value: str | None) -> str | None:
        if value is not None and not _ROLE_ARN.match(value):
            raise ValueError("Must be an IAM role ARN such as arn:aws:iam::123456789012:role/Name")
        return value


class AwsAccountPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    account_id: str
    name: str
    regions: list[str]
    role_arn: str | None
    created_at: datetime


class AwsAccountVerification(BaseModel):
    expected_account_id: str
    caller_account_id: str
    caller_arn: str
    matches: bool
