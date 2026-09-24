import re

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    """Trim, lowercase and sanity-check an email address (not a full RFC parser)."""
    email = value.strip().lower()
    if not _EMAIL_PATTERN.match(email):
        raise ValueError("Enter a valid email address")
    return email
