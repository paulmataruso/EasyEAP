import '@fontsource-variable/plus-jakarta-sans'
import '@fontsource-variable/red-hat-mono'
import './concept.css'
import type { ConceptModule } from '../contract'
import { Root } from './app/Root'

// Concept C · Premium Minimalist Glass (UI/UX Pro Max: Minimalism & Swiss Style, dark).
// Top navigation only, borderless list rows, full-page flows; one sentence leads every screen.
const concept: ConceptModule = {
  id: 'c',
  name: 'Premium Minimalist Glass',
  skill: 'UI/UX Pro Max',
  summary: 'Swiss-minimal dark console with a glass top bar and no sidebar. One plain sentence leads every screen; detail lives in hairline list rows that expand in place, and multi-step tasks open as full-page focused flows.',
  Root,
}
export default concept
