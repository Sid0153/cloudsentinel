from pydantic import BaseModel


class SandboxControlPublic(BaseModel):
    key: str
    title: str
    description: str
    rule_id: str  # the security rule that flags the insecure setting
    insecure: bool  # current state in the simulated AWS
    insecure_by_default: bool  # state after a reset


class SandboxState(BaseModel):
    account_id: str
    region: str
    controls: list[SandboxControlPublic]


class SandboxControlUpdate(BaseModel):
    insecure: bool
