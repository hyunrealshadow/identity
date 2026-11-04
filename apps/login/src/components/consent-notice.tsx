import { Info } from 'lucide-react'

/// Closing note under a consent decision, set apart by a divider.
export function ConsentNotice({ message }: { message: string }) {
  return (
    <div className="mt-5 flex items-start gap-2 border-t border-border pt-4 text-xs leading-5 text-muted">
      <Info className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <p>{message}</p>
    </div>
  )
}
