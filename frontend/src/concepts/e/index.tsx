import type { ConceptModule } from '../contract'

// Placeholder — replaced by the concept builder.
const concept: ConceptModule = {
  id: 'e',
  name: 'Concept E',
  skill: 'Impeccable',
  summary: 'Not built yet.',
  Root: ({ screen }) => <div style={{ padding: 40, color: '#ccc', background: '#111', minHeight: '100vh' }}>Concept E — {screen}</div>,
}
export default concept
