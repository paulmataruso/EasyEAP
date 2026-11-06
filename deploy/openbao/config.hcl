# EasyEAP PKI service (OpenBao). Listens only on the internal pki network.
ui            = false
disable_mlock = true
api_addr      = "http://easyeap-pki:8200"

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true # internal network only; never published
}

# Unattended unseal from a 32-byte key file. The supervisor seeds it from the openbao_unseal_key Docker secret on
# first start and replaces it when a backup is restored (the backup carries its own key, encrypted). Without this key
# the PKI data cannot be decrypted. See DEPLOYMENT.md, "Backup and restore".
seal "static" {
  current_key_id = "easyeap-1"
  current_key    = "file:///openbao/state/unseal.key"
}

audit "file" "easyeap-file" {
  options {
    file_path = "/openbao/logs/audit.log"
  }
}
