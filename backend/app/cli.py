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
    bk = sub.add_parser("backup", help="Full encrypted backup and restore (the same engine as the console)")
    bsub = bk.add_subparsers(dest="action", required=True)
    bc = bsub.add_parser("create", help="Make a backup; with --stdout the file is written to standard output")
    bc.add_argument("--passphrase-file", required=True, help="File with the passphrase ('-' reads one line from standard input)")
    bc.add_argument("--stdout", action="store_true", help="Write the backup to standard output and remove the server copy")
    br = bsub.add_parser("restore", help="Restore a backup file that is on this container's backups volume or piped in")
    br.add_argument("--file", default="-", help="Backup file inside the container, or '-' to read it from standard input")
    br.add_argument("--passphrase-file", required=True, help="File with the passphrase (not '-' when the backup comes from standard input)")
    br.add_argument("--yes", action="store_true", help="Confirm that every tenant, CA and setting on this server is replaced")
    sub.add_parser("restore-recover", help="Finish or roll back a restore interrupted by a restart (run at API start)")
    args = parser.parse_args(argv)

    if args.cmd == "restore-recover":
        from app.backup.engine import recover
        outcome = recover()
        if outcome:
            print(f"An interrupted restore was {outcome}.", file=sys.stderr)
        return 0
    if args.cmd == "backup":
        return _backup_cli(args)

    from app import models as m
    from app.db import platform_session

    if args.cmd == "bootstrap":
        from app.pki.openbao import bootstrap
        bootstrap()
        with platform_session() as s:
            if (s.scalar(select(func.count()).select_from(m.Admin)) or 0) == 0:
                from app.secrets_store import ensure_setup_token
                ensure_setup_token()
                print("EasyEAP is ready for first-run setup. Print the setup token with: docker compose exec easyeap-api easyeap setup-token", file=sys.stderr)
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
    return 1


def _read_passphrase(path: str) -> str:
    raw = sys.stdin.readline() if path == "-" else open(path, encoding="utf-8").read()
    return raw.strip("\r\n")


def _backup_cli(args) -> int:
    import shutil

    from app import audit
    from app.backup import engine
    from app.backup.bundle import BundleError
    try:
        if args.action == "create":
            rec = engine.start_backup(audit.Actor("system", "easyeap backup CLI"), _read_passphrase(args.passphrase_file), wait=True)
            rec, path = engine.get_backup(rec["id"])
            if rec.get("status") != "done":
                print(f"error: {rec.get('error') or 'the backup failed'}", file=sys.stderr)
                return 1
            if args.stdout:
                with open(path, "rb") as f:
                    shutil.copyfileobj(f, sys.stdout.buffer)
                engine.mark_downloaded(rec["id"], audit.Actor("system", "easyeap backup CLI"))
                engine.delete_backup(rec["id"])
            else:
                print(path)
            print(f"Backup {rec['file_name']}: {rec['size']} bytes, SHA-256 {rec['sha256']}", file=sys.stderr)
            return 0
        if args.action == "restore":
            if not args.yes:
                print("Restoring replaces every tenant, certificate authority, administrator and setting on this server. Re-run with --yes.", file=sys.stderr)
                return 2
            if args.file == "-" and args.passphrase_file == "-":  # noqa: S105 — "-" means standard input
                print("error: the backup is read from standard input, so give the passphrase in a file.", file=sys.stderr)
                return 2
            passphrase = _read_passphrase(args.passphrase_file)
            rid, partial = engine.new_upload_path()
            if args.file == "-":
                with open(partial, "wb") as out:
                    shutil.copyfileobj(sys.stdin.buffer, out)
            else:
                shutil.copyfile(args.file, partial)
            engine.finish_upload(rid, partial, "cli")
            engine.start_restore(rid, passphrase, actor_label="easyeap backup CLI", source="cli", wait=True)
            st = engine.restore_state() or {}
            if st.get("status") != "done":
                print(f"error: {st.get('error') or 'the restore failed'}", file=sys.stderr)
                return 1
            for w in st.get("warnings", []):
                print(f"note: {w}", file=sys.stderr)
            print("Restore complete. Sign in with an administrator account from the backup.", file=sys.stderr)
            return 0
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
