# EasyEAP lab: Samba Active Directory domain controller with LDAPS (self-signed). Test use only.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision krb5-user winbind ldb-tools ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* && rm -f /etc/samba/smb.conf
COPY entrypoint.sh seed.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/seed.sh
EXPOSE 389 636
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
