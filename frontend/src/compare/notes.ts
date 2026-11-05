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
    strengths: ['Pending critique'],
    weaknesses: ['Pending critique'],
    provenance: 'UI/UX Pro Max --design-system "enterprise security admin dashboard dark glassmorphism" (density 7, variance 4). Glassmorphism style, Fira Sans + Fira Code, slate + status green.',
  },
  b: {
    thesis: 'Dense operations board: icon rail, live service strip, streaming authentication feed and slide-over drawers.',
    strengths: ['Pending critique'],
    weaknesses: ['Pending critique'],
    provenance: 'UI/UX Pro Max --design-system "network operations monitoring real-time dashboard" (density 9, variance 6). Real-time ops pattern; Barlow / Barlow Condensed from typography retry; Cinzel rejected.',
  },
  c: {
    thesis: 'Quiet, spacious console: top navigation, a single posture statement, few large numbers and full-page focused flows.',
    strengths: ['Pending critique'],
    weaknesses: ['Pending critique'],
    provenance: 'UI/UX Pro Max --design-system "premium minimal dark saas admin" (density 4, variance 2). Minimalism & Swiss style; Plus Jakarta Sans from typography retry; Cormorant and light palette rejected.',
  },
  d: {
    thesis: 'TIA-606 administration labeling: every tenant, VLAN, group and certificate carries a structured identifier and a cable colour code used identically across every screen.',
    strengths: ['Pending critique'],
    weaknesses: ['Pending critique'],
    provenance: 'Impeccable concept-seed (seed:09984bb950ed7066), assigned direction: grounded candidate 3 (telecom administration labeling standard).',
  },
  e: {
    thesis: 'Transit-diagram NOC: the authentication path (controllers → SSIDs → policy → VLANs) drawn as lines with live events travelling them.',
    strengths: ['Pending critique'],
    weaknesses: ['Pending critique'],
    provenance: 'Impeccable concept-seed (seed:09984bb950ed7066), grounded candidate 2 (transit diagrams), raised by the emission-line and star-atlas challengers.',
  },
  f: {
    thesis: 'Security-printed credentials: certificates as document data pages with machine-readable lines; every access decision explained as a ledger.',
    strengths: ['Pending critique'],
    weaknesses: ['Pending critique'],
    provenance: 'Impeccable concept-seed (seed:09984bb950ed7066), Impeccable’s pick: grounded candidate 1 (security printing / identity documents).',
  },
}
