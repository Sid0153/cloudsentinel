"""Best-effort removal of secrets from log text. Standard library only."""

import logging
import re

_REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS access key IDs (long-term AKIA..., temporary ASIA...)
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    # JSON Web Tokens: three base64url segments, the first starting with "eyJ"
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "[REDACTED_JWT]"),
    # Authorization header values
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer " + _REDACTED),
    # key=value / "key": "value" for well-known secret names
    (
        re.compile(
            r"(?i)(\b(?:password|passwd|secret|secret_access_key|aws_secret_access_key|"
            r"token|api[_-]?key)\b[\"']?\s*[=:]\s*[\"']?)([^\s,\"'}]+)"
        ),
        r"\1" + _REDACTED,
    ),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Redacts the fully formatted message. Unformatted args are dropped afterwards."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True
