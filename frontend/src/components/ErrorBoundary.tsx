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
        <div className="max-w-lg rounded-md border border-rose-800 bg-rose-950/40 p-4 text-sm text-rose-100">
          <h1 className="mb-1 text-base font-bold">AttackLens hit a display error</h1>
          <p className="text-rose-200">The data is fine; this screen could not be drawn. Reload to try again.</p>
          {/* Plain text only, truncated; error messages may contain log-derived strings. */}
          <pre className="mt-2 whitespace-pre-wrap break-all rounded bg-slate-950 p-2 font-mono text-[11px] text-slate-300">
            {String(error.message).slice(0, 300)}
          </pre>
          <button type="button" onClick={this.reset} className="mt-3 rounded bg-rose-700 px-3 py-1 font-semibold text-white hover:bg-rose-600">
            Try again
          </button>
        </div>
      </div>
    )
  }
}
