# Security rules

Each rule has two parts:

| Part | Where | Contains |
|---|---|---|
| Metadata | `security-rules/rules/<RULE-ID>.yaml` | Title, category, default severity, what it detects, why it matters, remediation, limitations, references |
| Check | `backend/app/rules/checks/*.py` | A pure Python function: one normalized resource in, `PASS` / `FAIL` (with evidence) / `UNKNOWN` out |

The backend refuses to start if a metadata file has no check, a check has no metadata file, a
field is missing, or a severity or category is not one of the allowed values. YAML is read with
`yaml.safe_load`, so a rule file cannot execute code.

## Rules

| ID | Title | Resource | Default severity | Can change to |
|---|---|---|---|---|
| CS-SG-001 | Security group allows SSH from the internet | Security group | HIGH | |
| CS-SG-002 | Security group allows RDP from the internet | Security group | HIGH | |
| CS-SG-003 | Security group allows broad inbound access from the internet | Security group | MEDIUM | HIGH (all ports, or a sensitive service such as a database) |
| CS-S3-001 | S3 bucket is publicly accessible | S3 bucket | HIGH | CRITICAL (public write through the ACL) |
| CS-S3-002 | S3 bucket has no default encryption configured | S3 bucket | MEDIUM | |
| CS-IAM-001 | IAM user with a console password has no MFA | IAM user | MEDIUM | HIGH (the user also has broad permissions) |
| CS-IAM-002 | IAM identity has overly broad permissions | IAM user, IAM role | MEDIUM | HIGH (full administrator access) |
| CS-CT-001 | No multi-region CloudTrail trail is logging | AWS account | HIGH | MEDIUM (only single-region trails are logging) |

Each YAML file explains its severity rules (`severity_note`) and what the check does not look
at (`limitations`).

## Outcomes

- **PASS**: the resource was evaluated and is compliant, or the rule does not apply to it (for
  example CS-IAM-001 on a user with no console password).
- **FAIL**: becomes a finding, with evidence taken only from the collected configuration.
- **UNKNOWN**: the data the rule needs could not be read (for example `GetBucketAcl` was
  denied). It is never treated as a pass and never closes an existing finding.

## Adding a rule

Besides the steps below, add a switch for the rule to the sandbox (`CONTROLS` in
`backend/app/aws/sandbox.py`, see [docs/sandbox.md](../docs/sandbox.md)); a test fails while any
rule cannot be triggered there.


1. Write the check in `backend/app/rules/checks/<area>.py` with the `@check("CS-AREA-NNN",
   ResourceType...)` decorator. Return `Outcome.unknown(...)` whenever the data you need is `None`
   or listed in `unknown_checks`.
2. Add it to `ALL_CHECKS` in `backend/app/rules/registry.py`.
3. Add `security-rules/rules/CS-AREA-NNN.yaml` (copy an existing file).
4. Add a risk profile to `PROFILES` in `backend/app/risk/profiles.py` (see
   `docs/risk-model.md`). Put anything the score needs into the evidence.
5. Add tests with secure, vulnerable and unknown cases in `backend/tests/unit/`.
