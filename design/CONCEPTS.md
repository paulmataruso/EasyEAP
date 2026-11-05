# EasyEAP design concepts: comparison and decision

Six functional prototypes share one component layer, one synthetic data set (Brightline IT Services and four
tenants, demo clock 2026-11-05 10:42 UTC) and the same interactions. Run them with
`pnpm --dir frontend dev` and open `http://localhost:5173/design.html#/compare`. Keys 1–6 switch concept;
←/→ switch screen. Screenshots: `design/screenshots/<concept>/` (7 screens at 1440×900, full-page variants,
dashboard at 1920×1080 and 390×844).

| | Concept | Source | Critique | Signature move |
|---|---|---|---|---|
| A | Dark Glass Enterprise | UI/UX Pro Max | 26/40 | Glass depth encodes scope (tenant → record) |
| B | Modern Network Operations | UI/UX Pro Max | 27/40 | Live service strip; every value carries its age |
| C | Premium Minimalist Glass | UI/UX Pro Max | 24/40 | One posture sentence leads every screen |
| D | Refined Enterprise Admin | Impeccable | 26/40 | TIA-606 label tapes and the decision run |
| E | Advanced NOC | Impeccable | 27/40 | Transit-map authentication path |
| **F** | **Modern Security Management** | **Impeccable** | **27/40** | **Decision ledger; smoked glass with risk-keyed edges** |

## Method

- **UI/UX Pro Max** (A–C): `search.py --design-system` per concept, with persisted `design-system/easyeap-concept-*/MASTER.md`.
  Unsuitable font and palette results (Cinzel, Cormorant, a light palette) were rejected and retried with
  narrow `--domain` searches. `stack/scripts/design-audit.mjs` was run on the dashboard and certificates of
  every concept (`design/audit/`).
- **Impeccable** (D–F): `context`, `PRODUCT.md`, a shape brief and `concept-seed --scope direction --mode operate`
  (seed `09984bb950ed7066`), with the raises recorded in each spec.
- **Critique:** each of the six concepts got an Impeccable critique run as two isolated sub-agents.
  - Assessment A was a design review with live Playwright inspection.
  - Assessment B was `impeccable detect` plus the in-page `detect.js` overlay.
  - The synthesized reports are archived in `.impeccable/critique/`.
  - Detector note: the CLI scans source with regex only, so all six returned 0 source findings. The in-page
    overlay found the real ones (mono text shrunk below 12px in A, B and E; 10px label tapes in D; stragglers;
    long lines on the Policies note). Every false positive was adjudicated, including the sr-only chart tables
    and status callouts flagged as nested cards.

## What every reviewer found (the production console must fix these regardless of direction)

1. **Policy edits went live, silently, with no undo.** All six reviewers rated this P1. One click on "Block former
   employees" lets former staff back on. → Production: rule changes are staged as a **draft** with an
   **impact preview** (who changes decision or VLAN, computed server-side against the real directory), then
   **Publish**. Deny rules have no reorder arrows (their position never matters).
2. **Missing or stale authorization data shown as "Allowed".** → Production separates "allowed by policy" from
   "can connect" (valid certificate + RADIUS configured), shows tenants in setup as "Not enforceable yet",
   and states the fail-closed deadline as a time ("RADIUS keeps the snapshot from 10:12 and denies everyone
   from 10:12 tomorrow").
3. **The one-time shared secret could be dismissed unacknowledged**, and config snippets kept placeholders. →
   The secret step blocks dismissal until it is copied or acknowledged, and the vendor snippet is filled with
   the secret and the RADIUS address.
4. **Focus lost to `<body>` after dialogs, invisible focus in menus.** → Every dialog returns focus to its
   trigger or the changed row; `:focus-visible` everywhere; route changes focus the page heading.
5. **"Temporary hold" next to "cannot be undone".** → Removed. The backend never accepted `certificateHold`;
   revocation is permanent.
6. **Dates without years and "just now" for future times.** → One formatter with explicit years and true relative
   future ("in 5 days").
7. **Recovery buttons that dead-end** (e.g. "fix LDAPS trust" with nowhere to fix it). → Every fix names a
   destination that exists: Directory settings is a first-class screen.
8. **Small text from `em`-scaled mono.** → Fixed px type scale, 12px floor for data, 11px floor only for labels.

## Decision: Concept F as the base, with D's queue and E's palette

The build was asked to run without stopping for input, so this decision was made on the critique evidence.

**F wins on fit.**
- The product's core job is to find a person, explain why they get the network they get, and act. F is the
  only concept organised around that.
- The search-first shell scopes search to the tenant. It has `/` and ⌘K and keeps recently viewed items. A
  technician who visits a tenant monthly starts by typing a name.
- The decision ledger (account gate → certificate gate → deny wins → first allow → default → Access-Accept
  plus RFC 3580 attributes) is the most product-owned visual of the six. It reads the same on the user record,
  in Test-a-user and in the policy preview.
- F is the only concept where the pinned glassmorphism has a job. Smoked panels carry a 1px edge light keyed
  to risk.

**Taken from the others:**
- **D, needs-action queue first.** The dashboard leads with what will break next, ranked by blast radius
  and time-to-impact. A tenant-wide directory failure outranks single-certificate expiry. Each item gives one
  next action.
- **E, command palette that acts.** "Issue certificate for…", "Revoke…", "Rotate secret for…" and tenant switch.
- **B, freshness honesty.** Every status shows the age of its source data, never the poll age.
- **A and C, revoke flow.** A required reason and honest latency: new connections are rejected within seconds;
  connected sessions end on CoA or at the session timeout.

**Dropped from F:**
- **The MRZ line.** Reviewers called it costume, and its "check digits verify" read as cryptographic proof. It
  is replaced by fingerprint and chain verification, which is real.
- **Lifelines.** 365-day bars are indistinguishable. They are replaced by right-aligned "validity remaining"
  in tabular figures (the j-card raise).

**Rejected directions:**
- **A** is competent but category-generic.
- **B** suits an all-day NOC operator, which is the wrong persona.
- **C** is the weakest at daily work, and its headline sentence overclaims.
- **D**'s label language needs a stable label registry before it helps more than it decorates.
- **E**'s route map is excellent at a desk but breaks at 390px, and it leads with telemetry rather than tasks.
