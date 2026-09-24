"""The last line of defence: nothing secret-looking survives into audit details."""

from app.audit.service import MAX_TEXT, sanitize


def test_secret_looking_keys_are_dropped_at_any_depth() -> None:
    details = {
        "email": "a@example.com",
        "password": "hunter2-hunter2",
        "new_password": "x",
        "refresh_token": "abc",
        "nested": {"aws_secret_access_key": "k", "api_key": "k", "keep": 1},
    }
    assert sanitize(details) == {"email": "a@example.com", "nested": {"keep": 1}}


def test_secret_values_inside_strings_are_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
    cleaned = sanitize({"error": f"failed with {jwt} and AKIAABCDEFGHIJKLMNOP"})
    assert jwt not in cleaned["error"] and "AKIAABCDEFGHIJKLMNOP" not in cleaned["error"]


def test_only_plain_json_of_limited_size_is_kept() -> None:
    cleaned = sanitize({"text": "x" * 1000, "items": list(range(50)), "object": object()})
    assert len(cleaned["text"]) == MAX_TEXT
    assert len(cleaned["items"]) == 20
    assert isinstance(cleaned["object"], str)
    deep = sanitize({"a": {"b": {"c": {"d": {"e": 1}}}}})
    assert deep == {"a": {"b": {"c": {"d": "[truncated]"}}}}
