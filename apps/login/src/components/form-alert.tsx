import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { cn } from '@identity/ui/lib/utils'
import { CircleAlert } from 'lucide-react'

/** Request-level failure shown above or below a form */
export function ErrorAlert({
  title,
  message,
  className,
  animated = true,
}: {
  title?: string
  message: string
  className?: string
  animated?: boolean
}) {
  return (
    <Alert variant="destructive" className={cn(animated && 'auth-alert', className)}>
      <CircleAlert aria-hidden="true" />
      {title ? <AlertTitle>{title}</AlertTitle> : null}
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}
