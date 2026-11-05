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

# Unattended unseal from a 32-byte key file (Docker secret). Back this key up offline:
# without it the PKI data cannot be decrypted. See DEPLOYMENT.md, "Disaster recovery".
seal "static" {
  current_key_id = "easyeap-1"
  current_key    = "file:///run/secrets/openbao_unseal_key"
}

audit "file" "easyeap-file" {
  options {
    file_path = "/openbao/logs/audit.log"
  }
}
