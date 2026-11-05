---
target: design concept e
total_score: 27
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/paulmataruso/Dev_Workspace/EasyEAP/frontend/src/concepts/e"
timestamp: 2026-11-05T09-47-59Z
slug: frontend-src-concepts-e
---
Method: dual-agent (A: design-review sub-agent · B: detector/browser sub-agent)

# Critique: Concept E, "Advanced NOC" (Impeccable)

## Design Health Score
| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 2 | Status contradicts itself: a waiting controller is counted as degraded; the map stays healthy while the directory is stale |
| 2 | Match System / Real World | 3 | Plain failures; the success rate counts deliberate policy denials as failures |
| 3 | User Control and Freedom | 2 | Deny-rule toggle with no confirm; the inspector X discards the secret |
| 4 | Consistency and Standards | 3 | "Not configured" vs "Waiting for first request" for one state |
| 5 | Error Prevention | 2 | Register placeholders look like filled values |
| 6 | Recognition Rather Than Recall | 3 | Legends and menu hints |
| 7 | Flexibility and Efficiency | 3 | Ctrl+K deep-links, map arrow keys; no entity actions in the palette |
| 8 | Aesthetic and Minimalist Design | 3 | Coherent; snapshot age repeated three times |
| 9 | Error Recovery | 3 | The Rejected inspector reads like a diagnosis; recovery dead-ends |
| 10 | Help and Documentation | 3 | Good context, no glossary |
| **Total** | | **27/40** | **Acceptable** |

## Design Specificity Verdict
**LLM assessment.** Clearly authored. The route map (controllers, then policy interchange, then VLAN termini, with a Rejected line) does real work, has a Table alternative and keyboard access, and its grammar carries into PolicyRoute. Missed: the interchange never shows authorization freshness, the map breaks at 390px, and the panels are opaque.
**Deterministic scan.** CLI returned 0 findings (regex-only). The browser found 3:
- `tiny-text` 11.96px from `.mono { font-size: .92em }` (`concept.css:68`);
- a straggler;
- `nested-cards`, a probable false positive (a callout).
No page overflow; the map and table scroll inside their containers.
**Visual overlays.** Headless only.

## Overall Impression
The most memorable and genuinely functional signature, and the best diagnosis copy. It needs a freshness verdict and focus repair.

## What's Working
- The route map is a working instrument, not decoration.
- It explains rejections with "Fix:" lines.
- Honest-limits copy.

## Priority Issues
- **[P1] Fail-closed status gives no verdict and contradicts itself.** → /impeccable clarify
- **[P1] Policy edits have no guard.** → /impeccable harden
- **[P1] Focus management:** focus drops to body after create or revoke; the inspector traps Tab. → /impeccable harden
- **[P2] Setup and recovery dead-ends.** → /impeccable onboard
- **[P2] Copy misstates events:** "Revoked in 1 hour", and the CoA delivery claim is overstated. → /impeccable clarify

## Persona Red Flags
- **Alex:** the palette can't act on entities.
- **Sam:** 2.7:1 dimmed rows; focus lost; Tab trapped in the inspector.
- **Dana (MSP technician):** three clocks and no verdict at Northgate.

## Minor Observations
- Placeholder `<RADIUS_SERVER_IP>` in the snippet.
- At 390px the map shows only its station half.

## Questions to Consider
- What if the interchange itself carried authorization freshness?
- Should setup tenants see the map as the checklist?
