import { cn } from '@identity/ui/lib/utils'
import { Check } from 'lucide-react'

export interface StepperStep<T extends string> {
  id: T
  label: string
}

/**
 * Progress through a multi-step form. Finished and current steps can be
 * revisited; a step is only offered when `canSelect` allows it. Narrow
 * screens show a single progress line instead of every step.
 */
export function Stepper<T extends string>({
  label,
  steps,
  current,
  progress,
  canSelect,
  onSelect,
}: {
  label: string
  steps: ReadonlyArray<StepperStep<T>>
  current: T
  /** One line for narrow screens, such as "Step 2 of 5". */
  progress: string
  canSelect: (id: T) => boolean
  onSelect: (id: T) => void
}) {
  const currentIndex = Math.max(
    0,
    steps.findIndex((step) => step.id === current),
  )
  return (
    <nav aria-label={label}>
      <p className="text-sm text-muted-foreground sm:hidden">
        {progress}
        <span aria-hidden="true"> - </span>
        <span className="font-medium text-foreground">{steps[currentIndex]?.label}</span>
      </p>
      <ol className="hidden items-center gap-2 sm:flex">
        {steps.map((step, index) => {
          const status =
            index < currentIndex ? 'complete' : index === currentIndex ? 'current' : 'upcoming'
          const selectable = status !== 'current' && canSelect(step.id)
          const content = (
            <>
              <span
                className={cn(
                  'flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-semibold',
                  status === 'current' && 'border-foreground bg-foreground text-background',
                  status === 'complete' && 'border-foreground/20 bg-muted text-foreground',
                  status === 'upcoming' && 'border-border text-muted-foreground',
                )}
                aria-hidden="true"
              >
                {status === 'complete' ? <Check className="size-3.5" strokeWidth={2.5} /> : index + 1}
              </span>
              <span
                className={cn(
                  'truncate text-sm',
                  status === 'current' ? 'font-medium text-foreground' : 'text-muted-foreground',
                )}
              >
                {step.label}
              </span>
            </>
          )
          return (
            <li
              key={step.id}
              className="flex min-w-0 items-center gap-2"
              aria-current={status === 'current' ? 'step' : undefined}
            >
              {selectable ? (
                <button
                  type="button"
                  className="flex min-w-0 cursor-pointer items-center gap-2 rounded-md py-1 pr-1 outline-none hover:[&>span:last-child]:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50"
                  onClick={() => onSelect(step.id)}
                >
                  {content}
                </button>
              ) : (
                <span className="flex min-w-0 items-center gap-2 py-1 pr-1">{content}</span>
              )}
              {index < steps.length - 1 ? (
                <span
                  className={cn(
                    'h-px w-6 shrink-0 lg:w-10',
                    index < currentIndex ? 'bg-foreground/40' : 'bg-border',
                  )}
                  aria-hidden="true"
                />
              ) : null}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
