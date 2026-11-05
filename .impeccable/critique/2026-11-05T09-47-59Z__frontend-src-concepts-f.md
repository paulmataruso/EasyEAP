---
target: design concept f
total_score: 27
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/paulmataruso/Dev_Workspace/EasyEAP/frontend/src/concepts/f"
timestamp: 2026-11-05T09-47-59Z
slug: frontend-src-concepts-f
---
Method: dual-agent (A: design-review sub-agent · B: detector/browser sub-agent)

# Critique: Concept F, "Modern Security Management" (Impeccable)

## Design Health Score
| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 3 | The switcher says "All systems healthy" while RADIUS is degraded |
| 2 | Match System / Real World | 3 | Excellent failure copy; the MRZ and RFC codes leak jargon |
| 3 | User Control and Freedom | 2 | Live rule edits; X and Esc silently inert on the secret step |
| 4 | Consistency and Standards | 2 | Positions 1–6 vs "priority 90"; the switcher and table disagree |
| 5 | Error Prevention | 3 | Reason required, /8 refused, disabled accounts blocked; policy edits frictionless |
| 6 | Recognition Rather Than Recall | 3 | Recently viewed; decision snippets in rows |
| 7 | Flexibility and Efficiency | 3 | `/` and ⌘K search, arrow keys in the split list; no bulk |
| 8 | Aesthetic and Minimalist Design | 3 | Clean type hierarchy; the MRZ on every credential |
| 9 | Error Recovery | 3 | "Fix:" lines; LDAPS fix has no destination |
| 10 | Help and Documentation | 2 | No help entry or glossary |
| **Total** | | **27/40** | **Acceptable** |

## Design Specificity Verdict
**LLM assessment.** The decision ledger (account gate, then certificate gate, deny-wins, first allow, default, Access-Accept, then RFC 3580 reply attributes) is the most product-owned move of the six. The search-first shell fits the infrequent visitor and the core "find the user" flow. Weaknesses:
- The dashboard is a generic stat band.
- Lifelines are indistinguishable.
- The MRZ is costume.
- A bug: `[data-risk="valid"]` is missing from the CSS, so healthy credentials never show their edge light.
**Deterministic scan.** CLI returned 0 findings (regex-only). The browser found:
- `text-occlusion` ×10: false positives (the sr-only chart data table).
- `tiny-text`: the 11.5px "Synthetic demonstration data" footnote.
- Stragglers.
- `line-length` (about 98 characters) at `Policies.tsx:79`.
- `nested-cards`: a table well inside a panel.
The design review measured horizontal overflow at 390px on RADIUS (881px) and Certificates (404px); the detector checked only the dashboard.
**Visual overlays.** Headless only.

## Overall Impression
The best fit for the job ("find a person, explain the decision, act") and the best glass interpretation (smoked glass whose edge light carries risk). The dashboard needs to lead with a ranked queue, and the costume needs to go.

## What's Working
- The decision ledger, reused on the record and in Test-a-user, and faithful to fail-secure precedence.
- Copy at high-stakes moments (revoke consequences, plain-language LDAPS fix).
- The search-first shell with tenant scope, `/` and ⌘K, and recently viewed.

## Priority Issues
- **[P1] Policy edits are live, silent and can't be undone.** → /impeccable harden
- **[P1] Controller onboarding is in the wrong order:** the secret must be acknowledged before the snippet; placeholders. → /impeccable onboard
- **[P1] Cross-tenant status is misrepresented** (switcher health; Atlas "4 authorized"). → /impeccable harden
- **[P2] The signature move is weak where it counts:** lifelines, the missing valid edge, the MRZ. → /impeccable distill
- **[P2] Dashboard priority and mobile overflow.** → /impeccable layout, then /impeccable adapt

## Persona Red Flags
- **Alex:** no multi-select; the Issue picker is 42 Tab stops.
- **Sam:** focus lost after revoke; the revoke dialog's consequences are not in its description.
- **Dana (MSP technician):** the Directory fix has no destination; setup steps aren't links.

## Minor Observations
- VLAN 130's orange reads as failure next to the reject bars.
- Certificates auto-selects an expired certificate.

## Questions to Consider
- What if every write ended with the ledger as its receipt?
- Should policy adopt a draft, diff and publish commit model?
