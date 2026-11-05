import type { ConceptModule } from '../contract'

// Placeholder — replaced by the concept builder.
const concept: ConceptModule = {
  id: 'd',
  name: 'Concept D',
  skill: 'Impeccable',
  summary: 'Not built yet.',
  Root: ({ screen }) => <div style={{ padding: 40, color: '#ccc', background: '#111', minHeight: '100vh' }}>Concept D — {screen}</div>,
}
export default concept
