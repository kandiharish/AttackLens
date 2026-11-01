import { StrictMode, lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/geist'
import '@fontsource-variable/geist-mono'
import './index.css'
import App from './App.tsx'
import { ErrorBoundary } from './components/ErrorBoundary.tsx'

// Dev-only visual harness (`npm run dev`, then /?harness=run-stepper). import.meta.env.DEV is false in builds,
// so the harness chunk is dropped from production output.
const Harness = import.meta.env.DEV && new URLSearchParams(window.location.search).get('harness') === 'run-stepper' ? lazy(() => import('./dev/RunStepperHarness.tsx')) : null

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {Harness ? (
        <Suspense fallback={null}>
          <Harness />
        </Suspense>
      ) : (
        <App />
      )}
    </ErrorBoundary>
  </StrictMode>,
)
