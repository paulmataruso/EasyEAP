# EasyEAP API / worker image
FROM python:3.13-slim
ARG INSTALL_DEV=0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# pg_dump/pg_restore must match the server's major version (PostgreSQL 18), so the client comes from the PostgreSQL
# project's own Debian repository (set up by Debian's postgresql-common helper, which pins its signing key).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini postgresql-common \
 && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y \
 && apt-get install -y --no-install-recommends postgresql-client-18 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 easyeap && useradd -u 10001 -g easyeap -d /app -s /usr/sbin/nologin easyeap \
 && mkdir -p /var/lib/easyeap/secrets /var/lib/easyeap/backups /var/lib/easyeap/control \
 && chown -R easyeap:easyeap /var/lib/easyeap && chmod 0700 /var/lib/easyeap/secrets /var/lib/easyeap/backups /var/lib/easyeap/control
WORKDIR /app
COPY pyproject.toml ./
RUN mkdir app && touch app/__init__.py \
 && if [ "$INSTALL_DEV" = "1" ]; then pip install -e '.[dev]'; else pip install -e .; fi \
 && rm -rf app
COPY . .
RUN pip install --no-deps -e . && chown -R easyeap:easyeap /app
USER 10001:10001
# The named volume mounted here inherits this ownership on first use.
VOLUME ["/var/lib/easyeap/secrets", "/var/lib/easyeap/backups"]
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh", "api"]
