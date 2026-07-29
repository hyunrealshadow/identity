import { Button, Spinner } from '@heroui/react'
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

type SubmitButtonProps = ComponentProps<typeof Button>

/**
 * Submit button wired to the enclosing ProgressiveForm. While the enhanced
 * request is in flight, the clicked button shows a spinner through the
 * HeroUI `isPending` render prop; sibling submit buttons stay dimmed via the
 * form-level `aria-busy` styles.
 */
export function SubmitButton({ children, value, ...props }: SubmitButtonProps) {
  const { isPending, submitter } = useContext(FormPendingContext)
  const isCurrent =
    isPending && (submitter === null || submitter === (value ?? null))

  return (
    <Button type="submit" value={value} isPending={isCurrent} {...props}>
      {(renderProps) => (
        <>
          {renderProps.isPending ? (
            <Spinner color="current" size="sm" aria-hidden="true" />
          ) : null}
          {children}
        </>
      )}
    </Button>
  )
}
