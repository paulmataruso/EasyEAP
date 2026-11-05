#!/bin/sh
# Provision a lab domain on first start (state lives on /var/lib/samba), then run the DC in the foreground.
set -eu
REALM="${LAB_REALM:-LAB.EASYEAP.TEST}"
DOMAIN="${LAB_DOMAIN:-LAB}"
PASS="$(cat "${LAB_ADMIN_PASSWORD_FILE:-/run/secrets/lab_ad_password}")"
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  samba-tool domain provision --realm="$REALM" --domain="$DOMAIN" --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --adminpass="$PASS" --use-rfc2307 --option="tls enabled = yes" --option="ldap server require strong auth = yes" --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb"
  cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
  cp /etc/samba/smb.conf /var/lib/samba/smb.conf.saved
  ( sleep 15 && /usr/local/bin/seed.sh ) &
else
  cp /var/lib/samba/smb.conf.saved /etc/samba/smb.conf
fi
exec samba -i --debug-stdout
