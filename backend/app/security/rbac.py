"""Role-based access control. Platform roles apply to every tenant; tenant roles are granted per tenant."""
from __future__ import annotations

PLATFORM_ROLES = ("platform_owner", "platform_operator", "platform_auditor")
TENANT_ROLES = ("tenant_admin", "pki_admin", "wifi_admin", "auditor")

ROLE_LABELS = {
    "platform_owner": "Super Administrator (all tenants)",
    "platform_operator": "MSP Operator (all tenants)",
    "platform_auditor": "MSP Auditor (read-only, all tenants)",
    "tenant_admin": "Tenant Administrator",
    "pki_admin": "PKI Administrator",
    "wifi_admin": "Wi-Fi Administrator",
    "auditor": "Read-only Auditor",
}

READ = {"tenant:read", "identities:read", "certificates:read", "policy:read", "radius:read", "directory:read", "events:read", "audit:read"}

PERMISSIONS: dict[str, set[str]] = {
    # Issuing certificates is deliberately separate from managing certificate authorities.
    "wifi_admin": READ | {"identities:write", "certificates:issue", "certificates:revoke", "enrollment:manage", "policy:write", "radius:write", "directory:sync"},
    "pki_admin": READ | {"ca:manage", "templates:write", "certificates:issue", "certificates:revoke", "enrollment:manage"},
    "auditor": READ,
    "tenant_admin": READ | {
        "identities:write", "certificates:issue", "certificates:revoke", "enrollment:manage", "policy:write",
        "radius:write", "radius:secrets", "directory:write", "directory:sync", "ca:manage", "templates:write",
        "tenant:write", "enrollment:server_keygen",
    },
}
PERMISSIONS["platform_operator"] = PERMISSIONS["tenant_admin"] | {"tenants:create", "platform:read"}
PERMISSIONS["platform_auditor"] = READ | {"platform:read"}
PERMISSIONS["platform_owner"] = PERMISSIONS["platform_operator"] | {"platform:read", "platform:write", "admins:manage", "tenants:delete"}


def permissions_for(platform_role: str | None, tenant_roles: list[str]) -> set[str]:
    perms: set[str] = set()
    if platform_role:
        perms |= PERMISSIONS.get(platform_role, set())
    for role in tenant_roles:
        perms |= PERMISSIONS.get(role, set())
    return perms
