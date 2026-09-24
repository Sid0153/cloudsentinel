FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so this layer is cached when only application code changes.
COPY requirements.txt .
RUN pip install -r requirements.txt

RUN addgroup --system app && adduser --system --ingroup app app

COPY --chown=app:app app ./app
COPY --chown=app:app alembic ./alembic
COPY --chown=app:app alembic.ini docker-entrypoint.sh ./
# Rule metadata lives at the repository root, outside this build context. docker compose
# passes it as the extra build context "security_rules" (see docker-compose.yml). Without
# compose: docker build --build-context security_rules=security-rules backend
COPY --chown=app:app --from=security_rules rules ./security-rules/rules
ENV RULES_DIR=/app/security-rules/rules
RUN chmod +x docker-entrypoint.sh

USER app
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health/live', timeout=2)" || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
