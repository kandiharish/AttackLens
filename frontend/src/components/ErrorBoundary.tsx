import { Component, type ErrorInfo, type ReactNode } from 'react'

interface State {
  error: Error | null
}

/** Top-level boundary: a render error shows a readable message instead of a blank page. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('AttackLens UI error:', error, info.componentStack)
  }

  private reset = () => {
    history.replaceState(null, '', window.location.pathname + window.location.search)
    this.setState({ error: null })
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div role="alert" className="flex h-full items-center justify-center p-6">
        <div className="card max-w-lg p-6 text-[14px] text-ink">
          <h1 className="headline mb-1 text-[18px]">AttackLens hit a display error</h1>
          <p className="text-ink-2">The data is fine; this screen could not be drawn. Reload to try again.</p>
          {/* Plain text only, truncated; error messages may contain log-derived strings. */}
          <pre className="mt-3 rounded-lg border border-line bg-subtle p-3 font-mono text-[12px] break-all whitespace-pre-wrap text-ink">
            {String(error.message).slice(0, 300)}
          </pre>
          <button type="button" onClick={this.reset} className="focus-ring mt-4 h-9 rounded-full border border-ink bg-ink px-4 text-[13px] font-medium text-white hover:bg-[#262626]">
            Try again
          </button>
        </div>
      </div>
    )
  }
}
