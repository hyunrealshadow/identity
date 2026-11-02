import { useEffect, useRef, useState } from 'react'

import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'

/** Unmounting for authentication preserves the draft; explicit closing clears it. */
export function useDialogDraft<T>(
  key: string,
  isOpen: boolean,
  decode: (value: unknown) => T,
  empty: T,
  reset: () => void,
  encode: (value: T) => unknown = (value) => value,
) {
  const [value, setValue] = useState(() => decode(readDraft<unknown>(key)))
  const opened = useRef(false)
  const resetRef = useRef(reset)
  resetRef.current = reset
  const encodeRef = useRef(encode)
  encodeRef.current = encode
  useEffect(() => {
    if (isOpen) {
      opened.current = true
      return
    }
    if (!opened.current) return
    opened.current = false
    clearDraft(key)
    setValue(empty)
    resetRef.current()
  }, [key, isOpen, empty])
  useEffect(() => {
    if (isOpen) writeDraft(key, encodeRef.current(value))
  }, [key, isOpen, value])
  return [value, setValue] as const
}
