# Risk model (Phase 6)

Every finding gets a **risk score from 0 to 100** that says how urgently it should be fixed.
It is CloudSentinel's own, documented model. It is **not** CVSS or any other industry standard,
and it does not know your business (which bucket holds customer data, which instance is
production).

## Formula

```
risk = severity points + exposure points + impact points + confidence adjustment
       clamped to 0..100
```

The score is a **pure function of (rule, resource type, severity, evidence)**: no AWS call, no
database read, no randomness, no clock. The same finding with the same evidence always gets the
same score, and a stored finding can be re-scored at any time. Anything the score depends on is
put into the evidence by the rule (for example which attached instances have a public IP), so
the evidence also documents the score. Code: `backend/app/risk/`.

## Inputs and weights

| Factor | Question | Levels and points |
|---|---|---|
| Severity | How bad is this kind of problem? (from the rule, see `security-rules/`) | CRITICAL 50, HIGH 40, MEDIUM 25, LOW 10 |
| Exposure | How does an attacker reach it? | INTERNET 25, CONSOLE_LOGIN 20, CREDENTIALS 15, INDIRECT 10, LATENT 5, NONE 0 |
| Impact | What does the attacker get? | SEVERE 25, HIGH 20, MODERATE 15, LIMITED 10 |
| Confidence | Was everything needed for exposure and impact known? | HIGH 0, MEDIUM -5, LOW -10 |

Severity carries half of the maximum score because it is the rule author's expert judgement.
Exposure and impact then separate findings of the same severity using facts from *this*
account. When an input is missing, the profile assumes a cautious value (usually the worse
one) and lowers confidence, so the uncertainty is visible instead of hidden.

Exposure levels:

| Level | Meaning | Example |
|---|---|---|
| INTERNET | Anyone on the internet, now | Public bucket; open group on a running instance with a public IP |
| CONSOLE_LOGIN | The public AWS sign-in page, protected by a password only | Console user without MFA |
| CREDENTIALS | Needs this identity's password or access keys | Admin IAM user with active keys |
| INDIRECT | Needs another foothold first | Admin role; open group on private instances only |
| LATENT | Not reachable now, one change away | Unattached open group; admin user with no credentials |
| NONE | Not an entry point | Missing encryption at rest, missing CloudTrail |

## Per-rule profiles

`backend/app/risk/profiles.py` holds one small function per rule:

| Rule | Exposure from | Impact from | Lower confidence when |
|---|---|---|---|
| CS-SG-001/002 | internet-facing / private / no attached instances | HIGH (remote admin) | attachments unknown, or no EC2 attachments (other services are not collected) |
| CS-SG-003 | as above | SEVERE all ports, HIGH sensitive service, LIMITED otherwise | as above |
| CS-S3-001 | INTERNET | SEVERE public write, HIGH public read | |
| CS-S3-002 | NONE | LIMITED | |
| CS-IAM-001 | CONSOLE_LOGIN | SEVERE privileged, MODERATE otherwise | permissions unknown |
| CS-IAM-002 | user: CREDENTIALS or LATENT; role: INDIRECT | SEVERE full admin, HIGH service-wide | conditions present, or credential report missing |
| CS-CT-001 | NONE | MODERATE nothing logged, LIMITED some regions logged | |

A rule without a profile gets middle values and LOW confidence; a test makes sure every
shipped rule has one.

## Worked examples

These are the test cases in `backend/tests/unit/test_risk_scoring.py`.

| Finding | Severity | Exposure | Impact | Confidence | Score |
|---|---|---|---|---|---|
| Public bucket, anyone can write | 50 | 25 | 25 | 0 | **100** |
| SSH open, running instance with public IP | 40 | 25 | 20 | 0 | **85** |
| Public bucket, read only | 40 | 25 | 20 | 0 | **85** |
| Admin console user without MFA | 40 | 20 | 25 | 0 | **85** |
| SSH open, instance list unreadable (worst case assumed) | 40 | 25 | 20 | -5 | **80** |
| Admin IAM user with active access keys | 40 | 15 | 25 | 0 | **80** |
| Admin role | 40 | 10 | 25 | 0 | **75** |
| SSH open, private instances only | 40 | 10 | 20 | 0 | **70** |
| RDP open, group not attached | 40 | 5 | 20 | -5 | **60** |
| No multi-region CloudTrail logging | 40 | 0 | 15 | 0 | **55** |
| Bucket without default encryption | 25 | 0 | 10 | 0 | **35** |

## Interpretation

| Score | Priority | Suggested handling |
|---|---|---|
| 80-100 | P1 | Fix now: reachable and damaging |
| 60-79 | P2 | Fix soon |
| 40-59 | P3 | Plan a fix |
| 0-39 | P4 | Fix when convenient; mostly defence in depth |

Priorities are named P1-P4 so they are not confused with a rule's severity (a HIGH finding can
be P2 when it is not reachable).

Each finding stores `risk_score` and `risk_breakdown` (points and reason for every factor, the
priority and `model_version`). Each scan stores `risk_summary`: the highest score and the number
of findings per priority among the findings it detected, leaving out those an analyst marked
FALSE_POSITIVE. `GET /api/findings` sorts by risk by default and accepts `min_risk`.

## Limitations

- Weights and levels are judgement calls, chosen to be simple and explainable, not calibrated
  against incident data.
- It knows nothing about data sensitivity, business importance or compensating controls (a WAF,
  a VPN, network ACLs, SCPs).
- Exposure for security groups looks only at EC2 instances. Load balancers, RDS, Lambda and
  network ACLs or route tables are not considered.
- Role exposure is fixed at INDIRECT: trust policies are not analyzed, so a role anyone can
  assume is under-scored.
- Findings do not add up: ten P2 findings are not reported as one P1.
- A score is recomputed only when a scan detects the finding again. Findings created before
  Phase 6 have no score until then (`risk_score` is null and sorts last).
- Changing any number above is a new model version (`RISK_MODEL_VERSION`); old scores keep the
  version they were computed with until they are recomputed.
