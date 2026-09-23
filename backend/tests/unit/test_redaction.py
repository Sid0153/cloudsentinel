import logging

import pytest

from app.core.redaction import RedactingFilter, redact


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("login failed password=hunter2 for user", "hunter2"),
        ('payload {"password": "hunter2", "email": "a@b.c"}', "hunter2"),
        ("Authorization: Bearer abc.def-ghi_123", "abc.def-ghi_123"),
        ("key id AKIAIOSFODNN7EXAMPLE leaked", "AKIAIOSFODNN7EXAMPLE"),
        ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_nature-1 seen", "eyJhbGciOiJIUzI1NiJ9"),
    ],
)
def test_secrets_are_removed(raw: str, secret: str) -> None:
    assert secret not in redact(raw)


def test_ordinary_text_is_unchanged() -> None:
    message = "Scan 42 completed with 3 findings"
    assert redact(message) == message


def test_filter_redacts_formatted_log_record() -> None:
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1,
        msg="user %s password=%s", args=("alice", "hunter2"), exc_info=None,
    )
    RedactingFilter().filter(record)
    assert "hunter2" not in record.getMessage()
    assert "alice" in record.getMessage()
