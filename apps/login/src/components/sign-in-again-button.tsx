import { Button } from '@identity/ui/components/button'
import { useEffect, useState } from 'react'

interface SignInAgainButtonProps {
  label: string
  /** Resolves to the authorization URL to navigate to. */
  begin: () => Promise<string>
}

/** Starts a fresh account-selecting sign-in from the signed-out page. */
export function SignInAgainButton({ label, begin }: SignInAgainButtonProps) {
  const [starting, setStarting] = useState(false)

  // Going Back from the authorization page can restore this document from the
  // back/forward cache with the button still disabled; make it usable again.
  useEffect(() => {
    function clearRestoredStart(event: PageTransitionEvent) {
      if (event.persisted) setStarting(false)
    }
    window.addEventListener('pageshow', clearRestoredStart)
    return () => window.removeEventListener('pageshow', clearRestoredStart)
  }, [])

  async function start() {
    setStarting(true)
    try {
      window.location.assign(await begin())
    } catch {
      setStarting(false)
    }
  }

  return (
    <Button
      type="button"
      disabled={starting}
      onClick={() => void start()}
      className="mt-6 w-full"
    >
      {label}
    </Button>
  )
}
