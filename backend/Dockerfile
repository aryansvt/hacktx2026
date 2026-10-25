# build from the repo root so contracts/ is in the context:
#   docker build -f backend/Dockerfile -t hacktx-backend .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY contracts/py /srv/contracts/py
RUN pip install --no-cache-dir /srv/contracts/py

COPY backend/pyproject.toml /srv/backend/pyproject.toml
COPY backend/app /srv/backend/app
COPY backend/migrations /srv/backend/migrations
# editable so app/ stays next to migrations/, which it reads on startup
RUN pip install --no-cache-dir -e /srv/backend

WORKDIR /srv/backend
RUN useradd --system --no-create-home app
USER app

EXPOSE 8000
# caddy sits in front, so trust its forwarded headers for the client ip
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
