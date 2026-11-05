import { StrictMode, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { HashRouter, Route, Routes, useNavigate, useParams } from 'react-router'
import './design.css'
import { PrototypeStoreProvider } from './store'
import { Compare } from '@/compare/Compare'
import { lazyConceptRoot } from '@/concepts/registry'
import { SCREENS, type ScreenId } from '@/concepts/contract'
import type { ConceptModule } from '@/concepts/contract'

function ConceptRoute() {
  const { concept = 'a', screen = 'dashboard', entityId } = useParams()
  const navigate = useNavigate()
  const Root = lazyConceptRoot[concept as ConceptModule['id']]
  const screenId = (SCREENS.some((s) => s.id === screen) ? screen : 'dashboard') as ScreenId
  if (!Root) return <p>Unknown concept</p>
  return (
    <Suspense fallback={null}>
      <Root
        screen={screenId}
        entityId={entityId ?? (screenId === 'user' ? SCREENS.find((s) => s.id === 'user')!.sampleEntity : undefined)}
        navigate={(s, id) => navigate(`/c/${concept}/${s}${id ? `/${encodeURIComponent(id)}` : ''}`)}
      />
    </Suspense>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PrototypeStoreProvider>
      <HashRouter>
        <Routes>
          <Route path="/" element={<Compare />} />
          <Route path="/c/:concept/:screen" element={<ConceptRoute />} />
          <Route path="/c/:concept/:screen/:entityId" element={<ConceptRoute />} />
        </Routes>
      </HashRouter>
    </PrototypeStoreProvider>
  </StrictMode>,
)
