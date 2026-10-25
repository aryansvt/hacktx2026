# build from the repo root so the shared contracts package is in context:
#   docker build -f brain/Dockerfile -t hacktx-brain .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GEOIP_DB_PATH=/data/GeoLite2-City.mmdb \
    GEOIP_ASN_DB_PATH=/data/GeoLite2-ASN.mmdb

WORKDIR /app

COPY contracts/py /app/contracts/py
COPY brain/pyproject.toml /app/brain/pyproject.toml
COPY brain/brain /app/brain/brain

RUN pip install --no-cache-dir /app/contracts/py /app/brain \
    && useradd --system --uid 10001 brain

USER brain

# mount the geolite2 files here
VOLUME ["/data"]

CMD ["python", "-m", "brain"]
