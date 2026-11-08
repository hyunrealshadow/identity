import { Spinner } from '@identity/ui/components/spinner'

/**
 * Whole-page wait outside the workspace shell: startup, sign-in redirects and
 * callback completion. A spinner and one line, with no card around them. It
 * takes translated text so it also works before the locale provider mounts.
 */
export function FullPageLoading({ label }: { label: string }) {
  return (
    <main
      className="flex min-h-screen flex-col items-center justify-center gap-3 bg-background p-6 text-foreground"
      role="status"
      aria-live="polite"
    >
      <Spinner aria-hidden="true" />
      <p className="text-sm text-muted-foreground">{label}</p>
    </main>
  )
}
