---
target: design concept b
total_score: 27
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/paulmataruso/Dev_Workspace/EasyEAP/frontend/src/concepts/b"
timestamp: 2026-11-05T09-47-59Z
slug: frontend-src-concepts-b
---
Method: dual-agent (A: design-review sub-agent · B: detector/browser sub-agent)

# Critique: Concept B, "Modern Network Operations" (UI/UX Pro Max)

## Design Health Score
| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 3 | The strip and paused state are strong; under reduced motion the age chips freeze at "3s" |
| 2 | Match System / Real World | 3 | Plain failure text; Ana shows green "Allowed" with every certificate expired |
| 3 | User Control and Freedom | 2 | Live rule edits; Esc discards the one-time secret |
| 4 | Consistency and Standards | 3 | Three names for re-issue; reorder arrows on deny rules |
| 5 | Error Prevention | 2 | One click disables "Block former employees" |
| 6 | Recognition Rather Than Recall | 3 | Flyouts and kbd hints; the desktop rail is icon-only |
| 7 | Flexibility and Efficiency | 3 | j/k, `/`, pinned tenants; no global Issue, no palette, no bulk |
| 8 | Aesthetic and Minimalist Design | 2 | The dashboard repeats facts three times; 11–12px text dominates |
| 9 | Error Recovery | 3 | Specific form errors; the fix points to unreachable "directory settings" |
| 10 | Help and Documentation | 3 | Strong contextual popovers; no help entry |
| **Total** | | **27/40** | **Acceptable** |

## Design Specificity Verdict
**LLM assessment.** The logic is specific: freshness budgets tied to the fail-safe, and revocation previews that name this tenant's controllers. The visual form is the network-monitoring default: charcoal, cyan, condensed caps, KPI band. It is built for an all-day NOC operator, not PRODUCT's infrequent technician. The glass reads as opaque.
**Deterministic scan.** CLI returned 0 findings (regex-only). The browser found 94, almost all from 5 lines. One cause: unlayered `.b-mono { font-size: .9em }` (`concept.css:88`) overrides the Tailwind sizes, giving 10.8–11.7px text, ×77 on Certificates (one line repeated per row). Also an undersized clock (`ServiceStrip.tsx:249`) and `nested-cards` ×2: one false positive (a notice), one real (the result box at `Policies.tsx:248`). No mobile overflow.
**Visual overlays.** Headless only, not user-visible.

## Overall Impression
The most rigorous freshness model of the six, aimed at the wrong user.

## What's Working
- Revocation and secret flows are honest about limits.
- The freshness model is real: thresholds, hatched stale cells, an explicit paused state.
- The Tenants "Needs attention" list and 7-step setup checklist.

## Priority Issues
- **[P1] Security-critical edits have no guard,** and the secret drawer is dismissible. → /impeccable harden
- **[P1] The strip conflates poll age with data age.** Northgate's snapshot reads "3h" although it was built from 26h-old data. Fix: show source "as of" ages and derive freshness from the oldest input. → /impeccable clarify
- **[P1] Focus is lost or invisible.** `.b-menu-item { outline: none }` overrides focus-visible; flyouts open on focus; 32 Tabs to reach main content. → /impeccable audit
- **[P2] Mid-setup tenants get 8 empty telemetry panels instead of the checklist.** → /impeccable onboard
- **[P2] Validity dates drop the year,** and future times render as "just now". → /impeccable polish

## Persona Red Flags
- **Alex:** no global Issue and no bulk re-issue; j/k is missing in the stream.
- **Sam:** focus is invisible in flyouts; reduced motion shows a false "3s"; 11px text throughout.
- **Priya (MSP technician):** RADIUS "Healthy" next to Directory "Stale 26h"; the fix points to a screen that isn't in the nav.

## Minor Observations
- The Service health panel duplicates 4 of the 6 strip cells.
- At 390px the strip shows 2 of 6 cells with no scroll cue.

## Questions to Consider
- Who is the strip for?
- Should the dashboard follow the tenant's state (setup, then healthy, then degraded)?
