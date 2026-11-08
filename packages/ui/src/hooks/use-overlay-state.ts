import { useCallback, useMemo, useState } from "react"

export interface OverlayState {
  isOpen: boolean
  setOpen: (open: boolean) => void
  open: () => void
  close: () => void
  toggle: () => void
  onOpenChange: (open: boolean) => void
}

/**
 * Controlled open state for dialogs, sheets and menus.
 *
 * Handlers are stable so they can be passed to memoized children and used as
 * effect dependencies without re-running.
 */
export function useOverlayState(initial = false): OverlayState {
  const [isOpen, setOpen] = useState(initial)
  const open = useCallback(() => setOpen(true), [])
  const close = useCallback(() => setOpen(false), [])
  const toggle = useCallback(() => setOpen((current) => !current), [])

  return useMemo(
    () => ({ isOpen, setOpen, open, close, toggle, onOpenChange: setOpen }),
    [isOpen, open, close, toggle]
  )
}
