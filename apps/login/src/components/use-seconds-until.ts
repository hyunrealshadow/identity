import { useEffect, useState } from 'react'

/**
 * Whole seconds until `at`, counting down while the page is open. Rendered on
 * the server too, so a resend button starts disabled without JavaScript.
 */
export function useSecondsUntil(at: string | undefined) {
  const deadline = at ? Date.parse(at) : Number.NaN
  const remaining = () =>
    Number.isNaN(deadline) ? 0 : Math.max(0, Math.ceil((deadline - Date.now()) / 1000))
  const [seconds, setSeconds] = useState(remaining)
  useEffect(() => {
    setSeconds(remaining())
    if (Number.isNaN(deadline)) return
    const timer = window.setInterval(() => {
      const next = remaining()
      setSeconds(next)
      if (next <= 0) window.clearInterval(timer)
    }, 1000)
    return () => window.clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deadline])
  return seconds
}
