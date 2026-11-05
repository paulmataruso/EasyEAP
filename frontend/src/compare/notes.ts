// Concept notes shown on the comparison page. Strengths/weaknesses are filled from the
// Impeccable critiques and the UI/UX Pro Max audits (design/CONCEPTS.md has the full write-up).
export interface ConceptNotes {
  thesis: string
  strengths: string[]
  weaknesses: string[]
  provenance: string
  score?: string
}

export const CONCEPT_NOTES: Record<'a' | 'b' | 'c' | 'd' | 'e' | 'f', ConceptNotes> = {
  a: {
    thesis: 'Classic enterprise console in frosted glass: grouped sidebar, KPI band with history, health and activity side by side.',
    strengths: ["Decision trace reused on the user page, policy tester and Issue review", "Two-step revoke with per-controller CoA honesty; validation explains the fix", "Strong re-orientation: scope trail, tenant switcher with health"],
    weaknesses: ["Category-template composition (KPI band, 8/4 split); glass reads as flat cards", "Policy edits live and silent; missing directory data shown as Allowed", "Mono text shrinks to 11px; generic indigo–teal avatar gradient"],
    provenance: 'UI/UX Pro Max --design-system "enterprise security admin dashboard dark glassmorphism" (density 7, variance 4). Glassmorphism style, Fira Sans + Fira Code, slate + status green.',
    score: '26/40',
  },
  b: {
    thesis: 'Dense operations board: icon rail, live service strip, streaming authentication feed and slide-over drawers.',
    strengths: ["Freshness model is real: thresholds, hatched stale cells, explicit paused state", "Revocation preview names this tenant’s controllers with and without CoA", "Tenants page: needs-attention list and setup checklist"],
    weaknesses: ["Built for an all-day NOC operator, not an infrequent technician", "Strip conflates poll age with data age; dashboard repeats facts three times", "Invisible focus in flyouts; .9em mono gives 10.8–11.7px text"],
    provenance: 'UI/UX Pro Max --design-system "network operations monitoring real-time dashboard" (density 9, variance 6). Real-time ops pattern; Barlow / Barlow Condensed from typography retry; Cinzel rejected.',
    score: '27/40',
  },
  c: {
    thesis: 'Quiet, spacious console: top navigation, a single posture statement, few large numbers and full-page focused flows.',
    strengths: ["Posture sentence plus an attention list with consequences", "Best revocation reassurance; solid accessibility base", "Calm, readable, well-set type"],
    weaknesses: ["Signature sentence overclaims health and access", "Weakest for daily work: no search, palette, row actions or bulk", "Glass and tenant identity under-delivered"],
    provenance: 'UI/UX Pro Max --design-system "premium minimal dark saas admin" (density 4, variance 2). Minimalism & Swiss style; Plus Jakarta Sans from typography retry; Cormorant and light palette rejected.',
    score: '24/40',
  },
  d: {
    thesis: 'TIA-606 administration labeling: every tenant, VLAN, group and certificate carries a structured identifier and a cable colour code used identically across every screen.',
    strengths: ["Needs-action queue first: what, why, one fix", "Decision run (group → rule → VLAN tape) makes policy visible", "Most product-specific visual vocabulary"],
    weaknesses: ["Label tapes over-applied, unsearchable, 10px text", "Issued enrollment links leave no trace", "Fail-safe states misranked; recovery buttons dead-end"],
    provenance: 'Impeccable concept-seed (seed:09984bb950ed7066), assigned direction: grounded candidate 3 (telecom administration labeling standard).',
    score: '26/40',
  },
  e: {
    thesis: 'Transit-diagram NOC: the authentication path (controllers → SSIDs → policy → VLANs) drawn as lines with live events travelling them.',
    strengths: ["Route map is a working instrument with table and keyboard alternatives", "Rejected inspector reads like a diagnosis with Fix lines", "Command palette and map arrow keys"],
    weaknesses: ["No freshness verdict: map stays healthy while the directory is stale", "Focus drops after create/revoke; inspector traps Tab", "Map breaks at 390px; copy misstates past events"],
    provenance: 'Impeccable concept-seed (seed:09984bb950ed7066), grounded candidate 2 (transit diagrams), raised by the emission-line and star-atlas challengers.',
    score: '27/40',
  },
  f: {
    thesis: 'Security-printed credentials: certificates as document data pages with machine-readable lines; every access decision explained as a ledger.',
    strengths: ["Decision ledger: the most product-owned move, faithful to deny-wins precedence", "Search-first shell fits the infrequent visitor and the find-the-user flow", "Smoked glass with risk-keyed edge light gives glass a job"],
    weaknesses: ["MRZ line is costume; lifelines indistinguishable", "Dashboard lacks a ranked queue; mobile overflow on RADIUS/Certificates", "Switcher health disagrees with the Tenants table"],
    provenance: 'Impeccable concept-seed (seed:09984bb950ed7066), Impeccable’s pick: grounded candidate 1 (security printing / identity documents).',
    score: '27/40 · chosen',
  },
}
