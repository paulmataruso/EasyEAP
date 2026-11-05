import '@fontsource/barlow/latin-400.css'
import '@fontsource/barlow/latin-500.css'
import '@fontsource/barlow/latin-600.css'
import '@fontsource/barlow-condensed/latin-500.css'
import '@fontsource/barlow-condensed/latin-600.css'
import '@fontsource/jetbrains-mono/latin-400.css'
import '@fontsource/jetbrains-mono/latin-500.css'
import './concept.css'
import type { ConceptModule } from '../contract'
import { Shell } from './shell/Shell'

const concept: ConceptModule = {
  id: 'b',
  name: 'Modern Network Operations',
  skill: 'UI/UX Pro Max',
  summary:
    'NOC-style console: 56px icon rail with section flyouts, pinned-tenant tab strip, and a glass live service strip where every number carries its age and visibly goes stale. Dense 32px tables with inline filters and j/k navigation; slide-over inspectors.',
  Root: Shell,
}

export default concept
