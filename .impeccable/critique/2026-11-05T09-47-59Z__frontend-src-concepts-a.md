---
target: design concept a
total_score: 26
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/paulmataruso/Dev_Workspace/EasyEAP/frontend/src/concepts/a"
timestamp: 2026-11-05T09-47-59Z
slug: frontend-src-concepts-a
---
Method: dual-agent (A: design-review sub-agent · B: detector/browser sub-agent)

# Critique: Concept A, "Dark Glass Enterprise" (UI/UX Pro Max)

## Design Health Score
| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 3 | Data-as-of stamp, health dots and toasts are strong; policy edits give no visible feedback, and stale or missing directory data renders as green "Allowed" |
| 2 | Match System / Real World | 3 | Plain-language failure and revoke reasons; raw RADIUS reply attributes shown by default on the user page |
| 3 | User Control and Freedom | 2 | Policy toggle and reorder go live without undo; the one-time secret can be closed unacknowledged |
| 4 | Consistency and Standards | 3 | Three labels for the primary action; "15 expiring" vs "16 expire" on one card |
| 5 | Error Prevention | 2 | Excellent field validation (CIDR size explained), but tenant-wide rule changes take one click |
| 6 | Recognition Rather Than Recall | 3 | Scope trail is good; the secret has to be carried from step 2 into the step-3 snippet |
| 7 | Flexibility and Efficiency | 2 | Ctrl+K and `/` exist; no bulk actions; 14 Tabs to reach the primary call to action |
| 8 | Aesthetic and Minimalist Design | 3 | Restrained; the KPI tiles carry dead space |
| 9 | Error Recovery | 3 | Validation names the fix; Northgate's LDAPS error is raw OpenSSL text with a dead-end button |
| 10 | Help and Documentation | 2 | Inline explanation, no help entry point |
| **Total** | | **26/40** | **Acceptable** |

## Design Specificity Verdict
**LLM assessment.** The content is product-specific: the decision trace, CoA-honest revoke copy and vendor snippets. The composition is the category template: sidebar plus top bar, a 4-tile KPI band, an 8/4 chart and health split, and the slate/green Tailwind palette from a generator whose MASTER.md is tagged "Smart Home/IoT Dashboard". The signature move ("glass depth = scope") is too subtle to read.
**Deterministic scan.** CLI `impeccable detect` on `frontend/src/concepts/a` returned 0 findings, but it ran regex-only. Browser overlay: 80 hits from about 13 source locations:
- `ai-color-palette`: indigo-to-teal Avatar gradient, `ui/primitives.tsx:210`; one source line, 47 hits.
- `tiny-text`: `.a-mono { font-size: .92em }` at `concept.css:111` gives 11.04 and 11.96px; also 11px at `screens/Users.tsx:114`.
- `straggler` ×5, plus `line-length` (about 114 characters) at `screens/Policies.tsx:57`.
- `nested-cards` ×2: false positives (status callouts, not cards).
The detector caught the mono-shrink and avatar-gradient problems, which the design review missed.
**Visual overlays.** These ran in a headless browser, so the user never saw them.

## Overall Impression
A competent, honest enterprise console with the strongest decision-trace reuse. Visually it is the most generic of the six, and the glass reads as flat dark cards.

## What's Working
- The decision trace is reused on the user page, in the policy tester and in the Issue review step.
- The two-step revoke opens with focus on Cancel and gives per-controller CoA honesty.
- Re-orientation is strong: the All tenants › tenant › record trail and the switcher with health.

## Priority Issues
- **[P1] Policy edits are live, silent and can't be undone.** Moving "All staff" to position 1 sent 37 users to VLAN 100. Fix: a staged draft with an impact diff, then Publish and Undo. → /impeccable harden
- **[P1] Missing or stale authorization data is shown as "Allowed".** Atlas and Northgate show green rows. Fix: a "Pending" state and a fail-safe countdown. → /impeccable clarify
- **[P1] The one-time secret can be discarded unacknowledged,** and the snippet keeps placeholders. Fix: intercept the close and inject the secret and address into the snippet. → /impeccable harden
- **[P2] Focus is lost after dialogs,** and the Issue dialog opens on Close. → /impeccable audit
- **[P2] Signature depth is invisible, and the KPI band is the hero-metric template.** → /impeccable bolder

## Persona Red Flags
- **Alex:** no bulk re-issue for the 15 expiring certificates; moving a rule from 6 to 1 takes 5 clicks.
- **Sam:** focus goes to body after revoke; policy announcements omit the consequence.
- **Dana (MSP technician, infrequent visitor):** Northgate's banner leads to an all-green Users table, and there is no Directory destination where she could fix the cause.

## Minor Observations
- "Temporary hold" is offered under "cannot be undone".
- The nav repeats Certificates › Certificates.
- At 390px the reason column disappears from Recent authentications.

## Questions to Consider
- Should the loudest "Affects" treatment belong to tenant-wide changes?
- Does the KPI band earn its 260px?
