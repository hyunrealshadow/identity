import { cn } from '@identity/ui/lib/utils'
import { Minus } from 'lucide-react'
import { Fragment, type InputHTMLAttributes } from 'react'
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

const useIsomorphicLayoutEffect =
  typeof window === 'undefined' ? useEffect : useLayoutEffect

type SegmentedCodeInputProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  | 'autoComplete'
  | 'className'
  | 'defaultValue'
  | 'inputMode'
  | 'maxLength'
  | 'onChange'
  | 'onInput'
  | 'pattern'
  | 'value'
> & {
  className?: string
  defaultValue?: string
  groupClassName?: string
  inputClassName?: string
  isInvalid?: boolean
  onChange?: (value: string) => void
  slotClassName?: string
  value?: string
}

/**
 * A segmented code field of any shape: the presets below fix `length`,
 * `separatorAfter` and `normalize` for the codes this app knows, and callers
 * with another format describe their own.
 */
export type SegmentedCodeInputConfig = SegmentedCodeInputProps & {
  autoComplete: string
  inputMode: 'numeric' | 'text'
  length: number
  /** Renders a dash after this many characters, like `WDJB-MJHT`. */
  separatorAfter?: number
  normalize: (value: string) => string
  pattern: string
}

function normalizeTotp(value: string) {
  return value.replace(/\D/g, '').slice(0, 6)
}

/// Codes that are shown (and typed) as two groups of four: recovery codes and
/// the device codes of `RFC 8628` verification.
function normalizeGroupedCode(value: string) {
  return value.replace(/[^a-z0-9]/gi, '').toUpperCase().slice(0, 8)
}

/**
 * A segmented code field backed by one stable native input.
 *
 * The native input is what makes the field work without JavaScript (the form
 * posts the code) and keeps password managers useful: a pasted, formatted code
 * is normalized into that input's value instead of being dropped by a
 * controlled React value.
 */
export function SegmentedCodeInput({
  autoComplete,
  autoFocus,
  className,
  defaultValue = '',
  disabled,
  groupClassName,
  inputClassName,
  inputMode,
  isInvalid = false,
  length,
  normalize,
  onBlur,
  onChange,
  onFocus,
  pattern,
  separatorAfter,
  slotClassName,
  value,
  ...props
}: SegmentedCodeInputConfig) {
  const [internalValue, setInternalValue] = useState(() => normalize(defaultValue))
  const [isFocused, setIsFocused] = useState(false)
  const [isAutofocusPending, setIsAutofocusPending] = useState(
    Boolean(autoFocus && !disabled),
  )
  const inputRef = useRef<HTMLInputElement>(null)
  const currentValue = value === undefined ? internalValue : normalize(value)
  const lastValueRef = useRef(currentValue)
  const controlledValueRef = useRef(value)
  const onChangeRef = useRef(onChange)
  controlledValueRef.current = value
  onChangeRef.current = onChange
  // Separate square slots spread across the field width, styled like `Input`.
  const slotClasses = cn(
    'relative flex size-10 min-w-0 shrink items-center justify-center rounded-md border border-input bg-transparent text-base font-medium text-foreground shadow-xs transition-[color,box-shadow] dark:bg-input/30',
    'data-[active=true]:z-10 data-[active=true]:border-ring data-[active=true]:ring-3 data-[active=true]:ring-ring/50',
    'data-[invalid=true]:border-destructive data-[active=true]:data-[invalid=true]:ring-destructive/20 dark:data-[active=true]:data-[invalid=true]:ring-destructive/40',
    slotClassName,
  )

  const updateValue = useCallback(
    (nextValue: string) => {
      const normalized = normalize(nextValue)
      // Keep the real input's DOM value canonical so a form submit carries
      // the normalized code and ignored keystrokes cannot fill maxLength.
      const input = inputRef.current
      if (input && input.value !== normalized) input.value = normalized
      if (normalized === lastValueRef.current) return
      lastValueRef.current = normalized
      if (controlledValueRef.current === undefined) setInternalValue(normalized)
      onChangeRef.current?.(normalized)
    },
    [normalize],
  )

  useEffect(() => {
    lastValueRef.current = currentValue
  }, [currentValue])

  // Keep the native autofocus attribute for the no-JavaScript response, then
  // focus again after hydration because browsers do not consistently honor an
  // autofocus element inserted or reconciled by React.
  useIsomorphicLayoutEffect(() => {
    if (autoFocus && !disabled) {
      const input = inputRef.current
      input?.focus({ preventScroll: true })
      if (input && document.activeElement === input) setIsFocused(true)
    }
    setIsAutofocusPending(false)
  }, [autoFocus, disabled])

  // Mirror state into the real input without making it a React-controlled
  // value. React's controlled-value tracking restores the previous DOM value
  // on unrelated re-renders (e.g. focus), wiping a code that a password
  // manager just inserted ("flashes and disappears"). The first render is
  // skipped so a value filled before hydration is adopted, not overwritten.
  const hasRenderedRef = useRef(false)
  useEffect(() => {
    const input = inputRef.current
    if (input && hasRenderedRef.current && input.value !== currentValue) {
      input.value = currentValue
    }
    hasRenderedRef.current = true
  }, [currentValue])

  // Password managers may assign the native value directly.
  useEffect(() => {
    const input = inputRef.current
    if (!input) return

    const handleNativeInput = () => updateValue(input.value)
    input.addEventListener('input', handleNativeInput)
    // Adopt a value that a password manager placed before this effect ran
    // (autofill-on-load races React hydration).
    if (input.value && input.value !== lastValueRef.current) {
      updateValue(input.value)
    }
    return () => input.removeEventListener('input', handleNativeInput)
  }, [updateValue])

  const activeSlot = Math.min(currentValue.length, length - 1)
  const indexes = Array.from({ length }, (_, index) => index)
  const segments = separatorAfter && separatorAfter < length
    ? [indexes.slice(0, separatorAfter), indexes.slice(separatorAfter)]
    : [indexes]

  return (
    <div
      data-autofocus={isAutofocusPending ? 'true' : undefined}
      data-disabled={disabled ? 'true' : undefined}
      data-invalid={isInvalid ? 'true' : undefined}
      data-slot="input-otp"
      className={cn(
        'relative flex w-full items-center data-[disabled=true]:opacity-50',
        className,
      )}
    >
      <div
        data-slot="input-otp-group"
        className={cn('pointer-events-none flex w-full min-w-0 items-center justify-between gap-1', groupClassName)}
        aria-hidden="true"
      >
        {segments.map((segment, segmentIndex) => (
          <Fragment key={segment[0]}>
            {segmentIndex > 0 ? (
              <div data-slot="input-otp-separator" className="flex shrink-0 items-center text-muted-foreground">
                <Minus className="size-4" />
              </div>
            ) : null}
            <div className="contents">
              {segment.map((index) => {
                const char = currentValue[index]
                const isCurrent = index === activeSlot
                const isActive = isCurrent && (isFocused || isAutofocusPending)
                return (
                  <div
                    key={index}
                    data-active={isActive ? 'true' : undefined}
                    data-current={isCurrent ? 'true' : undefined}
                    data-disabled={disabled ? 'true' : undefined}
                    data-filled={char ? 'true' : undefined}
                    data-invalid={isInvalid ? 'true' : undefined}
                    data-slot="input-otp-slot"
                    className={slotClasses}
                  >
                    {char ? <div data-slot="input-otp-slot-value">{char}</div> : null}
                    {isActive && !char ? (
                      <div data-slot="input-otp-caret" className="h-4 w-px animate-caret-blink bg-foreground duration-1000" />
                    ) : null}
                  </div>
                )
              })}
            </div>
          </Fragment>
        ))}
      </div>
      <input
        {...props}
        ref={inputRef}
        name={props.name}
        defaultValue={currentValue}
        disabled={disabled}
        maxLength={separatorAfter && inputMode === 'text' ? length + 1 : length}
        pattern={pattern}
        inputMode={inputMode}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        aria-invalid={isInvalid || undefined}
        // Move password-manager badges beyond the slots without shrinking their layout.
        className={cn(
          'absolute inset-0 z-10 h-full w-[calc(100%+40px)] cursor-text border-0 bg-transparent text-transparent outline-none shadow-none [caret-color:transparent] [clip-path:inset(0_40px_0_0)]',
          inputClassName,
        )}
        onFocus={(event) => {
          setIsFocused(true)
          setIsAutofocusPending(false)
          onFocus?.(event)
        }}
        onBlur={(event) => {
          setIsFocused(false)
          onBlur?.(event)
        }}
      />
    </div>
  )
}

export function TotpInput(props: SegmentedCodeInputProps) {
  const { className, groupClassName, slotClassName, ...inputProps } = props
  return (
    <SegmentedCodeInput
      {...inputProps}
      className={className}
      groupClassName={groupClassName}
      slotClassName={slotClassName}
      length={6}
      separatorAfter={3}
      normalize={normalizeTotp}
      inputMode="numeric"
      pattern="^\d+$"
      autoComplete="one-time-code"
    />
  )
}

export function GroupedCodeInput(props: SegmentedCodeInputProps) {
  const { className, groupClassName, slotClassName, ...inputProps } = props
  return (
    <SegmentedCodeInput
      {...inputProps}
      className={className}
      groupClassName={groupClassName}
      slotClassName={slotClassName}
      length={8}
      separatorAfter={4}
      normalize={normalizeGroupedCode}
      inputMode="text"
      pattern="^[A-Za-z0-9-]+$"
      autoComplete="off"
      data-1p-ignore="true"
      data-bwignore="true"
      data-lpignore="true"
    />
  )
}
