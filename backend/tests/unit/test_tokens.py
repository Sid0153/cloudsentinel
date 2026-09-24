import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.auth.tokens import (
    ALGORITHM,
    ISSUER,
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)

KEY = "unit-test-signing-key-0123456789-abcdefghij"


def _claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": str(uuid.uuid4()),
        "iss": ISSUER,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "typ": "access",
    }
    claims.update(overrides)
    return claims


def test_round_trip_returns_the_user_id() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(user_id, KEY, timedelta(minutes=5))
    assert decode_access_token(token, KEY) == user_id


def test_expired_token_is_rejected() -> None:
    token = create_access_token(uuid.uuid4(), KEY, timedelta(minutes=-1))
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_token_signed_with_another_key_is_rejected() -> None:
    other_key = "a-different-key-0123456789-abcdefghijklmn"
    token = create_access_token(uuid.uuid4(), other_key, timedelta(minutes=5))
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_tampered_token_is_rejected() -> None:
    token = create_access_token(uuid.uuid4(), KEY, timedelta(minutes=5))
    header, payload, signature = token.split(".")
    tampered = ".".join([header, payload[:-2] + "AA", signature])
    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered, KEY)


def test_unsigned_token_with_alg_none_is_rejected() -> None:
    token = jwt.encode(_claims(), key="", algorithm="none")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_wrong_issuer_is_rejected() -> None:
    token = jwt.encode(_claims(iss="someone-else"), KEY, algorithm=ALGORITHM)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_wrong_token_type_is_rejected() -> None:
    token = jwt.encode(_claims(typ="refresh"), KEY, algorithm=ALGORITHM)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_missing_expiry_is_rejected() -> None:
    claims = _claims()
    del claims["exp"]
    token = jwt.encode(claims, KEY, algorithm=ALGORITHM)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_subject_that_is_not_a_uuid_is_rejected() -> None:
    token = jwt.encode(_claims(sub="not-a-uuid"), KEY, algorithm=ALGORITHM)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_garbage_is_rejected() -> None:
    with pytest.raises(InvalidTokenError):
        decode_access_token("definitely.not.a-jwt", KEY)


def test_refresh_tokens_are_unique_and_hash_is_stable() -> None:
    first, second = generate_refresh_token(), generate_refresh_token()
    assert first != second
    assert len(first) >= 48
    assert hash_refresh_token(first) == hash_refresh_token(first)
    assert hash_refresh_token(first) != hash_refresh_token(second)
    assert first not in hash_refresh_token(first)
