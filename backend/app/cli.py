"""Command-line helpers. Create the first administrator with:

    python -m app.cli create-admin --email you@example.com

The password is read from a hidden prompt (or CLOUDSENTINEL_ADMIN_PASSWORD for automation),
never from a command-line argument, so it does not end up in shell history.
"""

import argparse
import getpass
import os
import sys

from app.auth.passwords import validate_password_policy
from app.database.session import get_session_factory
from app.models.user import Role
from app.schemas.validators import normalize_email
from app.services.user_service import EmailAlreadyExistsError, create_user


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    create_admin = subcommands.add_parser("create-admin", help="Create an ADMIN user")
    create_admin.add_argument("--email", required=True)
    args = parser.parse_args(argv)
    return _create_admin(args.email)


if __name__ == "__main__":
    raise SystemExit(main())
