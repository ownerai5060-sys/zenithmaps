# Zenith Maps Platform API — local/staging image (not a hardened prod base).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements-api.txt requirements-api-extras.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements-api.txt -r requirements-api-extras.txt

COPY api/ api/
COPY sql/ sql/
COPY static/ static/
COPY zenith_client/ zenith_client/
COPY deploy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh \
    && mkdir -p /.data

EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
