# The simulated AWS for sandbox mode (docs/sandbox.md). Holds no data worth protecting and
# accepts any credentials, so it must only be reachable by the backend.
FROM python:3.12-slim

# MOTO_EC2_LOAD_DEFAULT_AMIS=false: moto's catalogue of real AMIs costs about 100 MB of
# memory; the sandbox needs none.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MOTO_EC2_LOAD_DEFAULT_AMIS=false

WORKDIR /app

# Locked with hashes, like the backend (see the command at the top of requirements.txt).
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt

RUN addgroup --system sandbox && adduser --system --ingroup sandbox sandbox

COPY --chown=sandbox:sandbox policy.py server.py ./

USER sandbox
EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/moto-api/', timeout=2)" || exit 1

CMD ["python", "server.py"]
