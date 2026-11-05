# EasyEAP API / worker image
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 easyeap && useradd -u 10001 -g easyeap -d /app -s /usr/sbin/nologin easyeap
WORKDIR /app
COPY pyproject.toml ./
RUN mkdir app && touch app/__init__.py && pip install -e '.[dev]' && rm -rf app
COPY . .
RUN pip install --no-deps -e . && chown -R easyeap:easyeap /app
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh", "api"]
