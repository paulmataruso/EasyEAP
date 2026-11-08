"""Certificate renewal settings (docs/plans/cert-renewal.md §3, §15a, §15b): what renews by itself and when, and how
the tenant's certificates stand."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.pki import renewal

router = APIRouter(prefix="/api/tenants/{tenant_id}/renewal", tags=["renewal"])


def renewal_out(ctx: TenantCtx) -> dict:
    s = ctx.session
    st = renewal.settings(s, ctx.id)
    tpls = s.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == ctx.id).order_by(m.CertificateTemplate.name)).all()
    return {
        "settings": {"user_certs": st.user_certs, "machine_certs": st.machine_certs, "server_cert": st.server_cert,
                     "renew_at_percent": st.renew_at_percent, "retire_superseded": st.retire_superseded,
                     "updated_at": st.updated_at.isoformat() if st.updated_at else None, "updated_by": st.updated_by},
        "limits": {"min_percent": renewal.MIN_PERCENT, "max_percent": renewal.MAX_PERCENT, "rollback_days": renewal.ROLLBACK_DAYS,
                   "silent_days": renewal.SILENT_DAYS, "quiet_days": renewal.QUIET_DAYS},
        # valid client certificates: auto (renew by themselves), silent, overdue, manual (need the user)
        "counts": renewal.counts(s, ctx.id),
        "templates": [{"id": str(t.id), "name": t.name, "purpose": t.purpose, "validity_days": t.validity_days,
                       "renew_before_days": t.renew_before_days, "group_policy": bool(t.autoenroll_kind)} for t in tpls],
        "server_certificate": renewal.server_status(s, ctx.id),
        "ca_schedule": renewal.ca_schedule(s, ctx.id),
    }


@router.get("")
def get_renewal(ctx: TenantCtx = Depends(require("certificates:read"))) -> dict:
    return renewal_out(ctx)


class RenewalIn(BaseModel):
    user_certs: bool
    machine_certs: bool
    server_cert: bool
    renew_at_percent: int = Field(ge=renewal.MIN_PERCENT, le=renewal.MAX_PERCENT)
    retire_superseded: bool | None = None  # None: unchanged


@router.put("")
def put_renewal(body: RenewalIn, ctx: TenantCtx = Depends(require("ca:manage"))) -> dict:
    s = ctx.session
    st = renewal.settings(s, ctx.id)
    before = {"user_certs": st.user_certs, "machine_certs": st.machine_certs, "server_cert": st.server_cert, "renew_at_percent": st.renew_at_percent,
              "retire_superseded": st.retire_superseded}
    after = body.model_dump(exclude_none=True)
    changes = {k: f"{before[k]} → {v}" for k, v in after.items() if before[k] != v}
    if not changes:
        return renewal_out(ctx)
    for k, v in after.items():
        setattr(st, k, v)
    st.updated_at, st.updated_by = datetime.now(UTC), ctx.actor.label
    templates = renewal.apply_to_templates(s, ctx.id, st.renew_at_percent) if "renew_at_percent" in changes else {}
    s.flush()
    audit.record(s, ctx.actor, "renewal.settings_updated", tenant_id=ctx.id, target_type="renewal", target_label="Certificate renewal",
                 detail={"changes": changes, "templates": templates})
    return renewal_out(ctx)
