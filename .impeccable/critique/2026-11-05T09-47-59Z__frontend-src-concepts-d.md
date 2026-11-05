---
target: design concept d
total_score: 26
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 4
target_identity: "file:/home/paulmataruso/Dev_Workspace/EasyEAP/frontend/src/concepts/d"
timestamp: 2026-11-05T09-47-59Z
slug: frontend-src-concepts-d
---
Method: dual-agent (A: design-review sub-agent · B: detector/browser sub-agent)

# Critique: Concept D, "Refined Enterprise Admin" (Impeccable)

## Design Health Score
| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 3 | Tenant health is always visible; an issued enrollment link leaves no trace |
| 2 | Match System / Real World | 3 | Plain failures; "SITE" is used for a tenant; Atlas shows "4 authorized" |
| 3 | User Control and Freedom | 2 | Live rule moves; the secret is lost on navigation |
| 4 | Consistency and Standards | 3 | Tapes look identical whether or not they are buttons; green means both selected and healthy |
| 5 | Error Prevention | 2 | Revoke is well guarded; policy edits are not |
| 6 | Recognition Rather Than Recall | 3 | VLAN shown as a code only (`HV·VL100`) |
| 7 | Flexibility and Efficiency | 2 | j/k on records; no bulk; can't search by label |
| 8 | Aesthetic and Minimalist Design | 3 | Clean ruled tables; a label column in every table |
| 9 | Error Recovery | 3 | Excellent field errors; recovery buttons dead-end |
| 10 | Help and Documentation | 2 | No help entry or glossary |
| **Total** | | **26/40** | **Acceptable** |

## Design Specificity Verdict
**LLM assessment.** The most product-specific vocabulary: the decision run (group tape, then rule tape, then VLAN tape), held to the TIA-606 labelling world. The needs-action queue first fits the infrequent visitor. Weaknesses:
- The tapes are over-applied wallpaper.
- The labels aren't searchable or stable.
- The pinned glass is almost absent.
**Deterministic scan.** CLI returned 0 findings (regex-only). The browser found these, all true positives:
- `undersized-ui-text`: 10px `.d-tape--sm` and 10.5px tapes and "SITE" (`concept.css:88,156,179`).
- `tiny-text`: 11px tenant domain.
- 3 stragglers.
No page overflow; tables scroll inside their containers.
**Visual overlays.** Headless only.

## Overall Impression
The strongest information architecture for the persona (the queue leads), with a signature language that needs to become a tool rather than decoration.

## What's Working
- A needs-action queue that states what is wrong, how to fix it, and gives one action.
- The decision run and Test-a-user make policy visible.
- Validation and consequence copy.

## Priority Issues
- **[P1] Issuing leaves no trace.** There is no pending enrollment row with resend or cancel. → /impeccable harden
- **[P1] Live policy edits have no preview or undo.** → /impeccable harden
- **[P1] Fail-safe states are misranked,** and their recovery buttons dead-end. → /impeccable clarify
- **[P1] Focus is lost after dialogs,** and there is no leave guard for the secret. → /impeccable harden
- **[P2] Tapes are decoration,** not stable, searchable identifiers. → /impeccable distill

## Persona Red Flags
- **Alex:** 7 expired certificates mean 7 dialogs; no jump-to-label.
- **Sam:** focus goes to body after every dialog; screen readers read the tapes letter by letter.
- **Dana (MSP technician):** routine expiries outrank the tenant-wide directory failure.

## Minor Observations
- The validity date drops the year.
- In the VLAN colour map, teal and green collapse together.
- 26px buttons on mobile.

## Questions to Consider
- If labels are the language, why can't I type one?
- Should the queue rank by blast radius and time-to-impact?
