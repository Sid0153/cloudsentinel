import pytest

from app.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    hash_password,
    validate_password_policy,
    verify_password,
)


def test_hash_verifies_and_is_argon2id() -> None:
    hashed = hash_password("a-decent-password")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "a-decent-password") is True


def test_wrong_password_is_rejected() -> None:
    assert verify_password(hash_password("a-decent-password"), "another-password") is False


def test_same_password_hashes_differently_because_of_salt() -> None:
    assert hash_password("a-decent-password") != hash_password("a-decent-password")


def test_garbage_hash_does_not_raise() -> None:
    assert verify_password("not-a-real-hash", "whatever") is False


def test_policy_accepts_boundary_lengths() -> None:
    assert validate_password_policy("x" * MIN_PASSWORD_LENGTH)
    assert validate_password_policy("x" * MAX_PASSWORD_LENGTH)


def test_policy_rejects_too_short_and_too_long() -> None:
    with pytest.raises(ValueError):
        validate_password_policy("x" * (MIN_PASSWORD_LENGTH - 1))
    with pytest.raises(ValueError):
        validate_password_policy("x" * (MAX_PASSWORD_LENGTH + 1))
