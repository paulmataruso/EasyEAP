---
target: design concept c
total_score: 24
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/paulmataruso/Dev_Workspace/EasyEAP/frontend/src/concepts/c"
timestamp: 2026-11-05T09-47-59Z
slug: frontend-src-concepts-c
---
Method: dual-agent (A: design-review sub-agent · B: detector/browser sub-agent)

# Critique: Concept C, "Premium Minimalist Glass" (UI/UX Pro Max)

## Design Health Score
| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 2 | The posture sentence says "healthy" above a degraded controller; "can join Wi-Fi" counts people with no certificate |
| 2 | Match System / Real World | 3 | Excellent plain language; the LDAPS error is raw OpenSSL |
| 3 | User Control and Freedom | 2 | Instant rule toggles; Esc discards the secret |
| 4 | Consistency and Standards | 3 | One controller labelled healthy, quiet and degraded on different screens |
| 5 | Error Prevention | 2 | Disabling a deny rule takes one click with no feedback |
| 6 | Recognition Rather Than Recall | 3 | Descriptive menus; no global search |
| 7 | Flexibility and Efficiency | 1 | No palette, shortcuts, row-level Issue or bulk actions |
| 8 | Aesthetic and Minimalist Design | 3 | Calm, but 8 stacked dashboard sections |
| 9 | Error Recovery | 2 | Strong explanations; "View people" is a dead end |
| 10 | Help and Documentation | 3 | Rich inline explanation |
| **Total** | | **24/40** | **Acceptable** |

## Design Specificity Verdict
**LLM assessment.** The copy is specific (computed posture sentences, CoA language); the visuals are any premium dark SaaS. The glass is limited to the nav and popovers, so it reads as dark minimalism. Tenants are visually identical, which is a real MSP risk.
**Deterministic scan.** CLI returned 0 findings (regex-only). The browser found 3, all true positives and all minor:
- 2 stragglers on the dashboard (no `text-wrap: pretty`);
- `line-length` on the uncapped `.c-note` at `Policies.tsx:65`.
No overflow at 390px.
**Visual overlays.** Headless only.

## Overall Impression
The cleanest reading experience, but its signature sentence overclaims, and it is the weakest for daily work.

## What's Working
- The posture sentence plus an attention list that states consequences.
- The best revocation reassurance of the six.
- A solid accessibility base (skip link, focus ring, aria-live counts).

## Priority Issues
- **[P1] The signature sentence overclaims health and access.** → /impeccable clarify
- **[P1] No countdown or fix path for the stale directory.** → /impeccable harden
- **[P1] Live policy edits have no guard.** → /impeccable harden
- **[P2] The core workflow is buried:** issuing takes 16 Tabs and there is no search. → /impeccable shape
- **[P2] Glass and tenant identity are under-delivered.** → /impeccable colorize

## Persona Red Flags
- **Alex:** every issue goes through a 4-step full-page flow.
- **Sam:** route changes are not announced; 30–32px targets on mobile.
- **Dana (MSP technician):** can't tell whether Northgate is locked out; Atlas says "4 of 4 can join" while still in setup.

## Minor Observations
- Validity dates drop the year.
- "1 certificate expire".
- Toasts cover the flow's Continue button.

## Questions to Consider
- What if the posture sentence had to be falsifiable?
- Should the deny deadline be a clock rather than a sentence?
