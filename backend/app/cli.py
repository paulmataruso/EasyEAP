"""`easyeap` management CLI (run inside the api container)."""
from __future__ import annotations

import argparse
import sys

from sqlalchemy import func, select


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="easyeap", description="EasyEAP management")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup-token", help="Print the one-time setup token (only before the first administrator exists)")
    sub.add_parser("bootstrap", help="Initialise OpenBao and the setup token (idempotent)")
    sub.add_parser("verify-audit", help="Verify the audit hash chain")
    rp = sub.add_parser("reset-admin-mfa", help="Turn off two-factor authentication for an administrator (break-glass)")
    rp.add_argument("email")
    sub.add_parser("recompute", help="Recompute every tenant's access decisions")
    bp = sub.add_parser("record-backup", help="Record a completed backup (called by deploy/backup.sh)")
    bp.add_argument("--file", required=True)
    bp.add_argument("--size", type=int, default=0)
    bp.add_argument("--encrypted", action="store_true")
    args = parser.parse_args(argv)

    from app import models as m
    from app.db import platform_session

    if args.cmd == "bootstrap":
        from app.pki.openbao import bootstrap
        bootstrap()
        with platform_session() as s:
            if (s.scalar(select(func.count()).select_from(m.Admin)) or 0) == 0:
                from app.secrets_store import ensure_setup_token
                ensure_setup_token()
                print("EasyEAP is ready for first-run setup. Print the setup token with: docker compose exec easyeap-api easyeap setup-token")
        return 0
    if args.cmd == "setup-token":
        with platform_session() as s:
            if (s.scalar(select(func.count()).select_from(m.Admin)) or 0) > 0:
                print("Setup is already complete; no setup token exists.", file=sys.stderr)
                return 1
        from app.secrets_store import ensure_setup_token
        print(ensure_setup_token())
        return 0
    if args.cmd == "verify-audit":
        from app.audit import verify_chain
        with platform_session() as s:
            ok, bad, n = verify_chain(s)
        print(f"{'OK' if ok else 'BROKEN'}: {n} rows verified" + (f", first bad row id {bad}" if bad else ""))
        return 0 if ok else 2
    if args.cmd == "reset-admin-mfa":
        from app import audit
        with platform_session() as s:
            a = s.scalars(select(m.Admin).where(m.Admin.email == args.email.lower())).first()
            if a is None:
                print("No such administrator", file=sys.stderr)
                return 1
            a.mfa_enabled, a.mfa_secret_ct = False, None
            audit.record(s, audit.Actor("system", "easyeap CLI"), "auth.mfa_reset_cli", target_type="admin", target_id=a.id, target_label=a.email)
        print("Two-factor authentication turned off. The administrator should set it up again after signing in.")
        return 0
    if args.cmd == "recompute":
        from app.policy.service import recompute_tenant
        with platform_session() as s:
            for t in s.scalars(select(m.Tenant)):
                print(t.slug, recompute_tenant(s, t.id))
        return 0
    if args.cmd == "record-backup":
        from datetime import UTC, datetime
        from app import audit
        with platform_session() as s:
            row = s.get(m.PlatformSetting, "last_backup") or m.PlatformSetting(key="last_backup", value={})
            row.value = {"at": datetime.now(UTC).isoformat(), "file": args.file, "size": args.size, "encrypted": args.encrypted}
            s.add(row)
            audit.record(s, audit.Actor("system", "deploy/backup.sh"), "system.backup_created", target_type="backup", target_label=args.file,
                         detail={"size": args.size, "encrypted": args.encrypted})
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
