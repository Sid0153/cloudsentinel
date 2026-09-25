"""Command-line helpers.

    python -m app.cli check-config      # run first by docker-entrypoint.sh
    python -m app.cli export-openapi    # writes docs/openapi.json
    python -m app.cli create-admin --email you@example.com
    python -m app.cli reconcile-scans   # run at startup by docker-entrypoint.sh
    python -m app.cli create-guest      # GUEST_EMAIL account for public demos (idempotent)
    python -m app.cli register-sandbox-account   # sandbox mode only (idempotent)

The password is read from a hidden prompt (or CLOUDSENTINEL_ADMIN_PASSWORD for automation),
never from a command-line argument, so it does not end up in shell history.
"""

import argparse
import getpass
import json
import os
import secrets
import sys
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.audit.events import AuditAction, TargetType
from app.audit.service import record
from app.auth.passwords import validate_password_policy
from app.aws.sandbox import SANDBOX_ACCOUNT_ID, SANDBOX_REGION
from app.core.config import get_settings
from app.database.session import get_engine, get_session_factory
from app.models.aws_account import AwsAccount
from app.models.user import Role
from app.rules.catalog import RuleCatalogError
from app.scans.service import reconcile_stale_scans
from app.schemas.validators import normalize_email
from app.services.rule_catalog import get_rule_catalog
from app.services.user_service import EmailAlreadyExistsError, create_user, get_user_by_email

SANDBOX_ACCOUNT_NAME = "Sandbox (simulated AWS)"


def _read_password() -> str:
    from_env = os.environ.get("CLOUDSENTINEL_ADMIN_PASSWORD")
    if from_env:
        return from_env
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise ValueError("Passwords do not match")
    return first


def _create_admin(email_arg: str) -> int:
    try:
        email = normalize_email(email_arg)
        password = validate_password_policy(_read_password())
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    with get_session_factory()() as db:
        try:
            create_user(db, email, password, Role.ADMIN)
        except EmailAlreadyExistsError:
            print("Error: a user with this email already exists", file=sys.stderr)
            return 1
    print(f"Created ADMIN user {email}")
    return 0


def _create_guest(role: Role) -> int:
    """Creates the GUEST_EMAIL account with a random password that is never shown.

    Visitors sign in through POST /api/auth/guest, never with a password. Safe to run on
    every start: an existing account is left as it is.
    """
    settings = get_settings()
    if settings.guest_email is None:
        print("Error: GUEST_EMAIL is not set", file=sys.stderr)
        return 1
    if role == Role.ADMIN:
        print("Error: the guest account must not be an ADMIN", file=sys.stderr)
        return 1
    with get_session_factory()() as db:
        if get_user_by_email(db, settings.guest_email) is not None:
            print(f"Guest account {settings.guest_email} already exists")
            return 0
        unusable_password = secrets.token_urlsafe(32) + "aA1!"
        create_user(db, settings.guest_email, unusable_password, role)
    print(f"Created guest account {settings.guest_email} ({role})")
    return 0


def _register_sandbox_account() -> int:
    """Registers the simulator's account so there is something to scan. Sandbox mode only."""
    if not get_settings().sandbox_enabled:
        print("Error: SANDBOX_AWS_ENDPOINT is not set", file=sys.stderr)
        return 1
    with get_session_factory()() as db:
        existing = db.scalar(select(AwsAccount).where(AwsAccount.account_id == SANDBOX_ACCOUNT_ID))
        if existing is not None:
            print("Sandbox AWS account already registered")
            return 0
        account = AwsAccount(
            account_id=SANDBOX_ACCOUNT_ID, name=SANDBOX_ACCOUNT_NAME, regions=[SANDBOX_REGION]
        )
        db.add(account)
        db.flush()
        record(
            db,
            AuditAction.AWS_ACCOUNT_REGISTERED,
            target_type=TargetType.AWS_ACCOUNT,
            target_id=account.id,
            details={
                "account_id": SANDBOX_ACCOUNT_ID,
                "name": SANDBOX_ACCOUNT_NAME,
                "regions": [SANDBOX_REGION],
                "via": "cli",
            },
        )
        db.commit()
    print(f"Registered sandbox AWS account {SANDBOX_ACCOUNT_ID}")
    return 0


def _check_config() -> int:
    """Fails fast, with a readable message, if the deployment is misconfigured.

    Messages name the setting and the problem, never its value (it may be a secret).
    """
    try:
        settings = get_settings()
    except ValidationError as error:
        print("Configuration errors:", file=sys.stderr)
        for problem in error.errors():
            name = ".".join(str(part) for part in problem["loc"]).upper() or "SETTINGS"
            print(f"  {name}: {problem['msg']}", file=sys.stderr)
        return 1
    try:
        rules = len(get_rule_catalog().rules)
    except RuleCatalogError as error:
        print(f"Rule catalog error: {error}", file=sys.stderr)
        return 1
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        # The driver's message can include the host and user, so it is not printed.
        print(
            "Cannot connect to the database: check DATABASE_URL and that PostgreSQL is running",
            file=sys.stderr,
        )
        return 1
    print(f"Configuration OK: APP_ENV={settings.app_env}, {rules} rules, database reachable")
    return 0


# docs/openapi.json at the repository root (backend/app/cli.py -> repository root).
OPENAPI_PATH = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def openapi_document() -> str:
    """The OpenAPI description as committed in docs/ (stable formatting for clean diffs)."""
    from app.main import create_app  # imported here: the other commands do not need the app

    return json.dumps(create_app().openapi(), indent=2, ensure_ascii=False) + "\n"


def _export_openapi() -> int:
    OPENAPI_PATH.write_text(openapi_document(), encoding="utf-8", newline="\n")
    print(f"Wrote {OPENAPI_PATH}")
    return 0


def _reconcile_scans() -> int:
    with get_session_factory()() as db:
        count = reconcile_stale_scans(db)
    print(f"Marked {count} interrupted scan(s) as FAILED")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    create_admin = subcommands.add_parser("create-admin", help="Create an ADMIN user")
    create_admin.add_argument("--email", required=True)
    subcommands.add_parser("reconcile-scans", help="Fail scans interrupted by a restart")
    subcommands.add_parser("check-config", help="Validate settings, rules and database access")
    subcommands.add_parser("export-openapi", help="Write docs/openapi.json")
    create_guest = subcommands.add_parser("create-guest", help="Create the GUEST_EMAIL account")
    create_guest.add_argument("--role", choices=["ANALYST", "VIEWER"], default="ANALYST")
    subcommands.add_parser(
        "register-sandbox-account", help="Register the simulated AWS account (sandbox mode)"
    )
    args = parser.parse_args(argv)
    if args.command == "create-guest":
        return _create_guest(Role(args.role))
    if args.command == "register-sandbox-account":
        return _register_sandbox_account()
    if args.command == "reconcile-scans":
        return _reconcile_scans()
    if args.command == "check-config":
        return _check_config()
    if args.command == "export-openapi":
        return _export_openapi()
    return _create_admin(args.email)


if __name__ == "__main__":
    raise SystemExit(main())
