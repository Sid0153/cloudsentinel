#!/bin/sh
set -e

# Apply pending migrations, then start the API. Fine for one container; with several
# replicas you would run migrations as a separate one-off job instead.
alembic upgrade head
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
