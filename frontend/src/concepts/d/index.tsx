import '@fontsource-variable/archivo/standard.css'
import '@fontsource-variable/martian-mono/standard.css'
import './concept.css'
import { Tooltip } from 'radix-ui'
import type { ConceptModule, ConceptProps } from '../contract'
import { useViewState, ViewStateProvider } from './model/state'
import { useRecordSnapshot } from './model/portfolio'
import { Shell } from './shell/Shell'
import { ToastProvider } from './ui/Toast'
import { Dashboard } from './screens/Dashboard'
import { Users } from './screens/Users'
import { UserDetail } from './screens/UserDetail'
import { Certificates } from './screens/Certificates'
import { Radius } from './screens/Radius'
import { Policies } from './screens/Policies'
import { Tenants } from './screens/Tenants'

function Screen({ screen, entityId, navigate }: ConceptProps) {
  switch (screen) {
    case 'dashboard': return <Dashboard navigate={navigate} />
    case 'users': return <Users navigate={navigate} />
    case 'user': return <UserDetail entityId={entityId} navigate={navigate} />
    case 'certificates': return <Certificates navigate={navigate} />
    case 'radius': return <Radius navigate={navigate} />
    case 'policies': return <Policies navigate={navigate} />
    case 'tenants': return <Tenants navigate={navigate} />
  }
}

function Frame(props: ConceptProps) {
  const { setPortal } = useViewState()
  useRecordSnapshot()
  return (
    <div data-concept="d">
      <ToastProvider>
        <Tooltip.Provider delayDuration={250}>
          <Shell {...props}>
            <Screen {...props} />
          </Shell>
        </Tooltip.Provider>
      </ToastProvider>
      <div ref={setPortal} />
    </div>
  )
}

function Root(props: ConceptProps) {
  return (
    <ViewStateProvider>
      <Frame {...props} />
    </ViewStateProvider>
  )
}

const concept: ConceptModule = {
  id: 'd',
  name: 'Refined Enterprise Administration',
  skill: 'Impeccable',
  summary:
    'TIA-606 administration labeling: every tenant, group, rule, VLAN, controller and certificate carries a label-tape identifier and a cable colour code, and 2px colour runs trace each decision from group to rule to VLAN.',
  Root,
}

export default concept
