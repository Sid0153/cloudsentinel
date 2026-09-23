from typing import Any

from app.core.config import Settings


def make_settings(**values: Any) -> Settings:
    """Build Settings from explicit values, ignoring any .env file on the machine.

    mypy treats the required fields as constructor arguments and rejects _env_file,
    so the type-check exception lives here once instead of in every test.
    """
    return Settings(_env_file=None, **values)  # type: ignore[call-arg,unused-ignore]