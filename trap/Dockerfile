# build from the repo root so the shared contracts package is in context:
#   docker build -f trap/Dockerfile -t hacktx-trap .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRAP_SSH_PORT=22 \
    TRAP_STATE_DIR=/state

WORKDIR /app

COPY contracts/py /app/contracts/py
COPY trap/pyproject.toml /app/trap/pyproject.toml
COPY trap/honeypot /app/trap/honeypot

RUN pip install --no-cache-dir /app/contracts/py /app/trap \
    && useradd --system --uid 10001 --no-create-home trap \
    && mkdir /state && chown trap:trap /state

# port 22 as non-root works because docker sets net.ipv4.ip_unprivileged_port_start=0
# in the container's network namespace (set explicitly in docker-compose.yml too).
# no setcap: it breaks exec under cap_drop ALL and is ignored with no-new-privileges.
USER trap

# host keys, spool, cursor and dead letter file. keep it so the fingerprint and
# unsent events survive restarts
VOLUME ["/state"]

EXPOSE 22
CMD ["python", "-m", "honeypot"]
