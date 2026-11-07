# EasyEAP API / worker image
# python-gssapi (Kerberos for Group Policy autoenrollment, docs/plans/gpo-autoenrollment.md) has no Linux wheels: build
# it here with the MIT Kerberos headers, and install only the wheel and the runtime library below.
FROM python:3.13-slim AS gssapi
RUN apt-get update && apt-get install -y --no-install-recommends gcc libkrb5-dev && rm -rf /var/lib/apt/lists/* \
 && pip wheel --no-cache-dir --wheel-dir /wheels 'gssapi>=1.9,<2'

FROM python:3.13-slim
ARG INSTALL_DEV=0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# pg_dump/pg_restore must match the server's major version (PostgreSQL 18), so the client comes from the PostgreSQL
# project's own Debian repository (set up by Debian's postgresql-common helper, which pins its signing key).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini postgresql-common libgssapi-krb5-2 \
 && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y \
 && apt-get install -y --no-install-recommends postgresql-client-18 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 easyeap && useradd -u 10001 -g easyeap -d /app -s /usr/sbin/nologin easyeap \
 && mkdir -p /var/lib/easyeap/secrets /var/lib/easyeap/backups /var/lib/easyeap/control \
 && chown -R easyeap:easyeap /var/lib/easyeap && chmod 0700 /var/lib/easyeap/secrets /var/lib/easyeap/backups /var/lib/easyeap/control
COPY krb5.conf /etc/krb5.conf
COPY --from=gssapi /wheels /tmp/wheels
RUN pip install /tmp/wheels/*.whl && rm -rf /tmp/wheels
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
