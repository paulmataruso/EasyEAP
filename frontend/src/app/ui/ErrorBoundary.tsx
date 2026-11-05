// Render-error fallback. A crash in one screen keeps the shell (sidebar, search, palette) and says what happened,
// instead of leaving a blank page. Changing resetKey (the route) clears it, so navigating away recovers.
import { Component, type ErrorInfo, type ReactNode } from 'react'
import { RefreshCw } from 'lucide-react'
import { Btn, Callout } from './index'

interface Props { children: ReactNode; resetKey?: string; fullPage?: boolean }
interface State { error: Error | null; key?: string }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, key: this.props.resetKey }

  static getDerivedStateFromError(error: unknown): Partial<State> {
    return { error: error instanceof Error ? error : new Error(String(error)) }
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('EasyEAP screen error:', error, info.componentStack)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div className={this.props.fullPage ? 'mx-auto max-w-[640px] px-4 py-16' : 'py-2'} role="alert">
        <Callout tone="crit" title="This page ran into a problem"
          action={<Btn size="sm" onClick={() => window.location.reload()}><RefreshCw aria-hidden />Reload</Btn>}>
          <p>Anything you already saved is kept. Reload the page{this.props.fullPage ? '' : ', or use the sidebar to go somewhere else'}.</p>
          <details className="mt-2">
            <summary className="ee-small cursor-pointer">Technical details</summary>
            <p className="ee-mono mt-1 break-words text-[12px]">{error.message}</p>
          </details>
        </Callout>
      </div>
    )
  }
}
