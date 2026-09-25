#!/bin/sh
# Starts the sandbox simulator in the background (restarted if it ever stops), waits until it
# answers, then hands over to the normal backend entrypoint. The simulator keeps its data in
# memory; the backend recreates the sandbox environment whenever it finds it empty.
set -e

(
    while true; do
        /opt/sandbox/venv/bin/python /opt/sandbox/server.py || true
        echo "Sandbox simulator stopped; restarting in 1 s" >&2
        sleep 1
    done
) &

python - <<'EOF'
import os
import sys
import time
import urllib.request

url = f"http://{os.environ['SANDBOX_HOST']}:{os.environ['SANDBOX_PORT']}/moto-api/"
for _ in range(60):
    try:
        urllib.request.urlopen(url, timeout=2)
        print("Sandbox simulator is up")
        sys.exit(0)
    except OSError:
        time.sleep(1)
print("Sandbox simulator did not start within 60 s", file=sys.stderr)
sys.exit(1)
EOF

exec ./docker-entrypoint.sh
