import { useCallback, useMemo, useState } from 'react'

export interface DialogState {
  isOpen: boolean
  open: () => void
  close: () => void
  setOpen: (open: boolean) => void
}

/** Controlled open state for a dialog whose opening is decided outside its trigger */
export function useDialogState(initial = false): DialogState {
  const [isOpen, setOpen] = useState(initial)
  const open = useCallback(() => setOpen(true), [])
  const close = useCallback(() => setOpen(false), [])
  return useMemo(() => ({ isOpen, open, close, setOpen }), [isOpen, open, close])
}
