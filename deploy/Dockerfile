# Single-container image for the free public deployment (docs/deployment.md): the backend
# plus the sandbox simulator, which listens on 127.0.0.1 only. Free hosting plans have no
# private services, and the simulator accepts any credentials, so it must never get its own
# public address. Build from the repository root:
#   docker build -f deploy/Dockerfile -t cloudsentinel-demo .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Both lockfiles are installed with hash checking. The simulator gets its own virtual
# environment so its dependencies (moto, Flask) never mix with the backend's.
COPY backend/requirements.txt ./requirements.txt
RUN pip install --require-hashes -r requirements.txt
COPY sandbox/requirements.txt /opt/sandbox/requirements.txt
RUN python -m venv /opt/sandbox/venv \
    && /opt/sandbox/venv/bin/pip install --require-hashes -r /opt/sandbox/requirements.txt

RUN addgroup --system app && adduser --system --ingroup app app

COPY --chown=app:app backend/app ./app
COPY --chown=app:app backend/alembic ./alembic
COPY --chown=app:app backend/alembic.ini backend/docker-entrypoint.sh deploy/start.sh ./
COPY --chown=app:app security-rules/rules ./security-rules/rules
COPY --chown=app:app sandbox/policy.py sandbox/server.py /opt/sandbox/
RUN chmod +x docker-entrypoint.sh start.sh

# MOTO_EC2_LOAD_DEFAULT_AMIS=false: moto's catalogue of real AMIs costs about 100 MB of
# memory, which matters on a 512 MB free instance; the sandbox needs none.
ENV RULES_DIR=/app/security-rules/rules \
    SANDBOX_HOST=127.0.0.1 \
    SANDBOX_PORT=5000 \
    SANDBOX_AWS_ENDPOINT=http://127.0.0.1:5000 \
    MOTO_EC2_LOAD_DEFAULT_AMIS=false

USER app
EXPOSE 10000

HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=5 \
    CMD python -c "import os, urllib.request as r; r.urlopen('http://127.0.0.1:%s/api/health/live' % os.environ.get('PORT', '8000'), timeout=2)" || exit 1

CMD ["./start.sh"]
