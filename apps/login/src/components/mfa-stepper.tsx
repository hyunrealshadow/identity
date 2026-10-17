import { Check } from 'lucide-react'

export function MfaStepper({ currentStep, label, steps }: { currentStep: number; label: string; steps: Array<string> }) {
  return (
    <ol className="mb-8 flex w-full" aria-label={label}>
      {steps.map((title, index) => {
        const number = index + 1
        const status = number < currentStep ? 'complete' : number === currentStep ? 'active' : 'inactive'
        return (
          <li
            key={title}
            className="relative flex min-w-0 flex-1 flex-col items-center text-center"
            data-status={status}
            aria-current={status === 'active' ? 'step' : undefined}
          >
            {index < steps.length - 1 ? (
              <span
                className={`absolute left-1/2 top-3.5 h-0.5 w-full ${status === 'complete' ? 'bg-success' : 'bg-separator'}`}
                aria-hidden="true"
              />
            ) : null}
            <span
              className={`relative z-10 flex size-7 items-center justify-center rounded-full border text-xs font-semibold ${status === 'complete' ? 'border-success bg-success text-white' : status === 'active' ? 'border-foreground bg-foreground text-background' : 'border-separator bg-background text-muted'}`}
              aria-hidden="true"
            >
              {status === 'complete' ? <Check className="size-4" strokeWidth={2.5} /> : number}
            </span>
            <span className={`mt-2 max-w-32 text-xs leading-4 ${status === 'active' ? 'font-semibold text-foreground' : status === 'complete' ? 'font-medium text-success' : 'text-muted'}`}>
              {stepTitle(title)}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

export function stepTitle(value: string) {
  return value
    .replace(/^第\s*\d+\s*步\s*/, '')
    .replace(/^Step\s+\d+\s+/i, '')
}
