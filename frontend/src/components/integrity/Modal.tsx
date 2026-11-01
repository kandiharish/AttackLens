// Accessible modal: role="dialog", aria-modal, labelled; focus trapped; Esc and backdrop close; focus returns to the opener.
// Rendered in a portal on document.body: a parent with backdrop-filter/transform (e.g. the sticky header) would
// otherwise become the containing block of the fixed overlay and clip it.
import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

interface Props {
  labelledBy: string
  describedBy?: string
  onClose: () => void
  children: ReactNode
  /** Tailwind max-width class of the panel. */
  width?: string
  /** Extra classes for the panel (border colour etc.). */
  className?: string
}

export function Modal({ labelledBy, describedBy, onClose, children, width = 'max-w-[640px]', className = '' }: Props) {
  const panel = useRef<HTMLDivElement>(null)
  const closeRef = useRef(onClose)
  useEffect(() => {
    closeRef.current = onClose
  })

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const el = panel.current
    const first = el?.querySelector<HTMLElement>('[data-autofocus]') ?? el?.querySelector<HTMLElement>(FOCUSABLE) ?? el
    first?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (!el) return
      // Only the top-most open modal reacts (a panel opened from a dialog sits above it).
      const all = document.querySelectorAll('[data-al-modal]')
      if (all[all.length - 1] !== el) return
      if (e.key === 'Escape') {
        e.stopPropagation()
        closeRef.current()
        return
      }
      if (e.key !== 'Tab') return
      const items = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((n) => n.offsetParent !== null || n === document.activeElement)
      if (items.length === 0) {
        e.preventDefault()
        el.focus()
        return
      }
      const a = items[0]
      const z = items[items.length - 1]
      if (e.shiftKey && (document.activeElement === a || !el.contains(document.activeElement))) {
        e.preventDefault()
        z.focus()
      } else if (!e.shiftKey && (document.activeElement === z || !el.contains(document.activeElement))) {
        e.preventDefault()
        a.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prevOverflow
      if (opener && document.contains(opener)) opener.focus()
    }
  }, [])

  return createPortal(
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center overflow-y-auto bg-ink/45 px-4 py-10 backdrop-blur-[2px] sm:py-16"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        ref={panel}
        data-al-modal=""
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={`w-full ${width} overflow-hidden rounded-2xl border bg-panel shadow-pop outline-none ${className}`}
      >
        {children}
      </div>
    </div>,
    document.body,
  )
}
