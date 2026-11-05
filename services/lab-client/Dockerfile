# EasyEAP lab: simulated 802.1X supplicant + controller (eapol_test from wpa_supplicant) and radclient.
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends eapoltest freeradius-utils openssl ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*
COPY simulate.sh /usr/local/bin/easyeap-simulate
RUN chmod +x /usr/local/bin/easyeap-simulate
ENTRYPOINT ["/usr/local/bin/easyeap-simulate"]
