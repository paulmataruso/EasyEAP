import type { ConceptModule } from '../contract'

// Placeholder — replaced by the concept builder.
const concept: ConceptModule = {
  id: 'a',
  name: 'Concept A',
  skill: 'UI/UX Pro Max',
  summary: 'Not built yet.',
  Root: ({ screen }) => <div style={{ padding: 40, color: '#ccc', background: '#111', minHeight: '100vh' }}>Concept A — {screen}</div>,
}
export default concept
