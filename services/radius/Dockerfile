# EasyEAP RADIUS: FreeRADIUS 3.2.10 + radius-agent (Python stdlib only).
FROM freeradius/freeradius-server:3.2.10
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /etc/raddb/sites-enabled/* /etc/raddb/mods-enabled/* \
 && mkdir -p /var/lib/easyeap-radius && chown -R freerad:freerad /var/lib/easyeap-radius /var/log/freeradius /var/run/freeradius
COPY agent/ /opt/easyeap-agent/
USER freerad
ENV EASYEAP_RADIUS_STATE=/var/lib/easyeap-radius PYTHONUNBUFFERED=1
VOLUME ["/var/lib/easyeap-radius"]
EXPOSE 1812/udp 1813/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD ["python3", "/opt/easyeap-agent/healthcheck.py"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/opt/easyeap-agent/easyeap_agent.py"]
