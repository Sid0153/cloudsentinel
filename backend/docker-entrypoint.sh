#!/bin/sh
set -e

# Check the configuration, apply pending migrations, fail scans that a previous container left
# unfinished, then start the API. Fine for one container; with several replicas you would run
# migrations as a separate one-off job and use a real job queue for scans.
python -m app.cli check-config
alembic upgrade head
python -m app.cli reconcile-scans
# Public demo setup (both commands leave existing data alone).
if [ -n "$SANDBOX_AWS_ENDPOINT" ]; then
    python -m app.cli register-sandbox-account
fi
if [ -n "$GUEST_EMAIL" ]; then
    python -m app.cli create-guest
fi
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
