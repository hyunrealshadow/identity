import { Button } from '@identity/ui/components/button'
import { cn } from '@identity/ui/lib/utils'
import {
  createContext,
  useContext,
  type ComponentProps,
} from 'react'

interface FormPendingState {
  isPending: boolean
  /** `value` attribute of the submitter that triggered the request. */
  submitter: string | null
}

export const FormPendingContext = createContext<FormPendingState>({
  isPending: false,
  submitter: null,
})

type SubmitButtonProps = Omit<ComponentProps<typeof Button>, 'type'> & {
  fullWidth?: boolean
}

/**
 * Native submit button wired to the enclosing ProgressiveForm. While the
 * enhanced request is in flight, all submit buttons in the form are disabled
 * and the clicked button shows a spinner.
 */
export function SubmitButton({
  children,
  value,
  fullWidth = false,
  disabled = false,
  className,
  ...props
}: SubmitButtonProps) {
  const { isPending, submitter } = useContext(FormPendingContext)
  const isCurrent =
    isPending && (submitter === null || submitter === (value ?? null))

  return (
    <Button
      type="submit"
      value={value}
      disabled={disabled || isPending}
      loading={isCurrent}
      data-pending={isCurrent ? '' : undefined}
      className={cn(fullWidth && 'w-full', className)}
      {...props}
    >
      {children}
    </Button>
  )
}
