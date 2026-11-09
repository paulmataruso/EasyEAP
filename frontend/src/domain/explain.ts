import type { FailureCode, RevocationReason, CertStatus, Platform, NasVendor } from './types'

/** Plain-language translations of RADIUS/TLS failure causes. Mirrors backend/app/radius/explain.py. */
export const failureExplanations: Record<FailureCode, { title: string; explanation: string; fix: string }> = {
  unknown_ca: {
    title: 'Certificate from an untrusted authority',
    explanation:
      'The device presented a certificate issued by an authority that this RADIUS server does not trust.',
    fix: 'Re-enroll the device so it receives a certificate from this tenant\'s issuing CA, or remove a stale certificate the device chose instead.',
  },
  cert_expired: {
    title: 'Certificate has expired',
    explanation: 'The device\'s certificate is past its expiry date, so the server refused it.',
    fix: 'Renew the certificate from the user\'s enrollment page and install the new package on the device.',
  },
  cert_revoked: {
    title: 'Certificate was revoked',
    explanation: 'This certificate was revoked by an administrator and can no longer be used to connect.',
    fix: 'If the device should still have access, issue it a new certificate. Revocation cannot be undone.',
  },
  cert_unknown: {
    title: 'Certificate not issued by EasyEAP',
    explanation:
      'The certificate chains to a trusted CA but EasyEAP has no record of issuing it, so it is treated as untrusted.',
    fix: 'Check for certificates issued outside EasyEAP from the same CA, then re-enroll the device.',
  },
  identity_unauthorized: {
    title: 'User is not authorized for network access',
    explanation: 'The certificate is valid, but none of the user\'s directory groups grant network access.',
    fix: 'Add the user to a group with an Allow rule, or add a rule for one of their groups.',
  },
  account_disabled: {
    title: 'Directory account is disabled or locked',
    explanation: 'Active Directory reports this account as disabled, locked out or deleted, so access is denied.',
    fix: 'Re-enable or unlock the account in Active Directory, then run a directory sync.',
  },
  policy_deny: {
    title: 'Denied by an access rule',
    explanation: 'An explicit Deny rule matched one of the user\'s groups. Deny rules always take precedence.',
    fix: 'Review the rule that denied access, or remove the user from the denied group.',
  },
  vlan_assignment: {
    title: 'VLAN could not be applied',
    explanation:
      'Authentication succeeded but the controller did not place the client on the assigned VLAN (it may not exist on the controller or interface group).',
    fix: 'Confirm the VLAN exists on the controller and that AAA override / RADIUS VLAN assignment is enabled on the SSID.',
  },
  snapshot_stale: {
    title: 'Authorization data is out of date',
    explanation:
      'The RADIUS server\'s copy of authorization data is older than the allowed maximum, so it failed safe and denied access.',
    fix: 'Check that the EasyEAP API and worker are running and that directory sync is succeeding.',
  },
  tls_handshake: {
    title: 'Secure handshake failed',
    explanation: 'The device and server could not complete the TLS handshake, often because the device does not trust the server certificate.',
    fix: 'Install the Root CA on the device and make sure its Wi-Fi profile names the RADIUS server certificate\'s hostname.',
  },
  client_timeout: {
    title: 'Device stopped responding',
    explanation: 'The device stopped answering midway through authentication. This often means it rejected the server certificate silently.',
    fix: 'Check the device trusts the Root CA and the server name in its Wi-Fi profile matches.',
  },
  network_not_enabled: {
    title: 'Network not enabled on this controller or switch',
    explanation: 'The request came from a network (Wi-Fi or wired) that this controller or switch isn\'t registered for in EasyEAP, so it was refused before the certificate was checked.',
    fix: 'If it should serve that network, edit it on the RADIUS page and turn the network on (for a switch, Add switch walks you through it).',
  },
  network_unknown: {
    title: 'Network couldn\'t be determined',
    explanation: 'EasyEAP couldn\'t tell whether this request came from Wi-Fi or a switch port, so it was refused.',
    fix: 'Register the controller or switch for one network only, or contact support with the event details.',
  },
  mab_unsupported: {
    title: 'Switch tried MAC Authentication Bypass',
    explanation: 'The switch asked EasyEAP to admit a device by its MAC address. EasyEAP only accepts EAP-TLS certificates, so the device was refused.',
    fix: 'Remove “mab” from the switch\'s port configuration (EasyEAP\'s generated configuration doesn\'t use it), or leave devices without 802.1X on ports that aren\'t configured for it.',
  },
  // MAC authentication on switch ports (docs/plans/mac-auth.md §5.2)
  mab_not_enabled: {
    title: 'MAC authentication isn\'t on for this switch',
    explanation: 'The switch or controller asked EasyEAP to admit a device by its MAC address, but MAC authentication isn\'t turned on for it in EasyEAP (or the request didn\'t come from a switch port), so the device was refused.',
    fix: 'To admit devices without 802.1X on this switch, open it on the RADIUS page and turn on MAC authentication. Wi-Fi MAC filtering isn\'t supported.',
  },
  mab_mismatch: {
    title: 'MAC address didn\'t match the switch\'s report',
    explanation: 'The MAC address the switch asked about differs from the device address it reported (Calling-Station-Id), so EasyEAP refused it rather than guess.',
    fix: 'Check the switch sends the device\'s MAC address in both (radius-server attribute 31 mac format ietf upper-case, and the default MAB user name).',
  },
  mab_password: {
    title: 'Unexpected MAC authentication password',
    explanation: 'In a MAC authentication request the password must be the device\'s MAC address. This one wasn\'t, so EasyEAP refused it.',
    fix: 'Remove any “mab request format” or custom MAB password settings from the switch.',
  },
  mac_unknown: {
    title: 'Device isn\'t on the MAC allow list',
    explanation: 'The switch asked EasyEAP to admit a device by its MAC address, and that address isn\'t on the MAC allow list.',
    fix: 'If the device belongs on the network, allow it from MAC allow list → Seen, not allowed. Otherwise nothing to do: it stays out (or in the unknown-device VLAN).',
  },
  mac_disabled: {
    title: 'Device is blocked on the MAC allow list',
    explanation: 'The device\'s MAC address is on the MAC allow list but blocked, so it was refused.',
    fix: 'Unblock it on the MAC allow list if it should have access again.',
  },
  mac_expired: {
    title: 'Device\'s MAC allow-list entry expired',
    explanation: 'The device\'s entry on the MAC allow list had an expiry date that has passed.',
    fix: 'Extend or remove the expiry on the MAC allow list if the device still needs access.',
  },
  mac_group_disabled: {
    title: 'Device\'s group is turned off',
    explanation: 'The device is on the MAC allow list, but its group is turned off, so every device in it is refused.',
    fix: 'Turn the group back on, or move the device to another group.',
  },
}

export const revocationReasonLabels: Record<RevocationReason, string> = {
  unspecified: 'Unspecified',
  keyCompromise: 'Key compromise (device lost or stolen)',
  affiliationChanged: 'User left or changed role',
  superseded: 'Replaced by a new certificate',
  cessationOfOperation: 'Device retired',
}

export const certStatusLabels: Record<CertStatus, string> = {
  active: 'Active',
  expiring: 'Expiring soon',
  expired: 'Expired',
  revoked: 'Revoked',
  pending: 'Pending',
}

export const platformLabels: Record<Platform, string> = {
  windows: 'Windows',
  macos: 'macOS',
  ios: 'iPhone & iPad',
  android: 'Android',
  linux: 'Linux',
}

export const vendorLabels: Record<NasVendor, string> = {
  'cisco-9800': 'Cisco Catalyst 9800',
  'cisco-aireos': 'Cisco AireOS WLC',
  'cisco-switch': 'Cisco Catalyst switch',
  unifi: 'UniFi Network',
  other: 'Other RADIUS client',
}
