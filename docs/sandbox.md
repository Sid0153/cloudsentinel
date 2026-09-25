# Sandbox mode and guest access

Sandbox mode runs the real CloudSentinel (API, database, rule engine, risk engine, audit log)
against a **simulated AWS account** instead of a real one. Guest access lets anyone try it
without an account. Together they make a public demo possible without an AWS account, without
credentials and without cost. Both are off unless configured.

## What is real and what is simulated

| Part | Sandbox mode |
|---|---|
| Web app, API, sign-in, roles, audit log, database | Real, unchanged |
| Scanning, rule engine, findings lifecycle, risk scores | Real, unchanged: the same code paths as for a real account |
| The AWS account being scanned | **Simulated**: [moto](https://github.com/getmoto/moto) running as its own server (`sandbox/`), account `123456789012`, region `us-east-1` |

The backend talks to the simulator over HTTP exactly as it talks to AWS. The only difference
is the endpoint address (`SANDBOX_AWS_ENDPOINT`) and fixed fake credentials. Anything shown in
sandbox mode must be described as simulated, never as a real AWS account.

## Running it

```bash
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up --build
```

Open http://localhost:8080 and click **Explore as guest**. At startup the backend registers
the simulated account (`python -m app.cli register-sandbox-account`) and creates the guest
account (`python -m app.cli create-guest`). Both commands leave existing data alone. You can
still create an admin with `create-admin` and sign in normally.

`scripts/sandbox_smoke.py` checks the whole flow against a running stack (CI runs it on every
push): guest sign-in, scan, switch changes, second scan, findings opening and closing.

## The simulated environment

A small account with a bastion instance, three S3 buckets, two IAM users and a CloudTrail
trail. The **Sandbox** page has one switch per security rule. Each switch makes one setting
insecure or fixes it (`backend/app/aws/sandbox.py`):

| Switch | Rule | Default |
|---|---|---|
| SSH open to the internet | CS-SG-001 | insecure |
| Remote Desktop open to the internet | CS-SG-002 | secure |
| Database port open to the internet | CS-SG-003 | secure |
| Bucket readable by anyone | CS-S3-001 | insecure |
| Bucket without default encryption | CS-S3-002 | secure |
| Console user without MFA | CS-IAM-001 | insecure |
| Automation user with full admin rights | CS-IAM-002 | secure |
| Activity logging switched off | CS-CT-001 | insecure |

A test (`tests/unit/test_sandbox_environment.py`) scans the environment after flipping each
switch and checks that exactly that switch's rule changes, and that every rule in the catalog
has a switch. **A new rule therefore needs a new switch.**

The simulator keeps everything in memory. When it restarts (for example after a free hosting
plan stopped it), it is empty. The backend recreates the environment, with the default
switches, before showing the Sandbox page and before every scan, so a scan never mistakes an
empty simulator for "everything was fixed".

## Differences from real AWS

- **Bucket policy status.** moto does not implement `GetBucketPolicyStatus`. The sandbox image
  adds a simplified version (`sandbox/policy.py`): a policy is public if an Allow statement
  names the principal `*` without a Condition. Real AWS evaluates conditions in more detail.
- **S3 Control host names.** Real AWS puts the account ID in the S3 Control host name. The
  sandbox session removes that prefix so requests reach the simulator (`app/aws/session.py`).
- **Fixed identity.** The account ID is always `123456789012` and the caller is
  `arn:aws:sts::123456789012:user/moto`.
- **Everything else** is whatever moto implements, which covers every call the scanner makes.
  In the default environment, scans complete without errors and without "unknown" results.

## How sandbox mode is kept away from real AWS

1. `SANDBOX_AWS_ENDPOINT` must be an http(s) URL, and the app refuses to start if it points at
   an AWS host (`amazonaws.com`, `amazonaws.com.cn`, `api.aws`).
2. In sandbox mode every session uses fixed fake credentials. The real credential chain is
   never read, so no real key can be sent anywhere.
3. The code that *changes* the environment (`app/aws/sandbox.py`) is only reached through the
   Sandbox API, which builds its clients from the sandbox endpoint and answers 404 in normal
   mode. The scanner itself stays read-only, and the IAM policy test still checks every call
   the scanner makes.
4. The simulator accepts any credentials, so it is never published: in Docker Compose only the
   backend can reach it (CI checks that it has no host port binding).

## Guest access

Set `GUEST_EMAIL` (the sandbox override defaults it to `guest@cloudsentinel.example`). The
login page then shows **Explore as guest**, which calls `POST /api/auth/guest` and signs the
visitor in as that account without a password.

| Safeguard | Why |
|---|---|
| The guest must not be an ADMIN (refused at sign-in and by `create-guest`) | A configuration mistake cannot hand out administration to everyone |
| Default role ANALYST (`create-guest --role VIEWER` for read-only) | Visitors can start scans and use the sandbox, but not manage users, AWS accounts or read the audit log |
| No usable password (random, never shown); `change-password` refuses the guest | Nobody can take the shared account over or lock others out |
| Account lockout does not block guest sign-in | Lockout protects a password; the guest has none that anyone knows |
| A replayed guest refresh token ends only that session | Normally a replay ends every session of the user; for a shared account that would sign out every visitor |
| Rate limits per client IP: sign-in (10/min), scans started (3/min), sandbox changes (30/min) | Keyed by IP, not by user, because all visitors share one user |
| Every guest action is in the audit log with `actor_email` = the guest and the client IP | Abuse stays traceable |

Guest access also works in normal mode, but then visitors see real scan results: only enable it
with a real account you are happy to show publicly.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `SANDBOX_AWS_ENDPOINT` | unset | Sandbox mode: every AWS call goes to this URL |
| `GUEST_EMAIL` | unset | Guest access as this account |
| `SCAN_RATE_LIMIT_PER_MINUTE` | 3 | Scans a client IP may start per minute |
| `SANDBOX_RATE_LIMIT_PER_MINUTE` | 30 | Sandbox changes a client IP may make per minute |

The limits live in process memory (see `core/rate_limit.py`), which suits the single backend
container this project runs.
