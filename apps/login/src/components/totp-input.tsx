import { inputOTPVariants } from '@heroui/react'
import type { InputHTMLAttributes } from 'react'
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'

const useIsomorphicLayoutEffect =
  typeof window === 'undefined' ? useEffect : useLayoutEffect

type SegmentedCodeInputProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  | 'autoComplete'
  | 'className'
  | 'defaultValue'
  | 'id'
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
  variant?: 'primary' | 'secondary'
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
  variant = 'primary',
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
  const slots = useMemo(() => inputOTPVariants({ variant }), [variant])
  const slotClasses = useMemo(
    () => slots.slot({ className: slotClassName }),
    [slotClassName, slots],
  )
  const slotValueClasses = useMemo(
    () => slots.slotValue(),
    [slots],
  )
  const caretClasses = useMemo(() => slots.caret(), [slots])

  const updateValue = useCallback(
    (nextValue: string) => {
      const normalized = normalize(nextValue)
      if (normalized === lastValueRef.current) return
      lastValueRef.current = normalized
      // Keep the real input's DOM value canonical so a form submit carries
      // the normalized code even when a password manager pasted formatting.
      const input = inputRef.current
      if (input && input.value !== normalized) input.value = normalized
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

  return (
    <div
      data-input-otp-container
      data-autofocus={isAutofocusPending ? 'true' : undefined}
      data-disabled={disabled ? 'true' : undefined}
      data-invalid={isInvalid ? 'true' : undefined}
      data-slot="input-otp"
      className={slots.base({
        className: ['w-fit max-w-full', className]
          .filter(Boolean)
          .join(' '),
      })}
    >
      <div
        data-input-otp-group
        data-slot="input-otp-group"
        className={slots.group({
          className: ['pointer-events-none items-center', groupClassName]
            .filter(Boolean)
            .join(' '),
        })}
        aria-hidden="true"
      >
        {Array.from({ length }, (_, index) => {
          const char = currentValue[index]
          const isCurrent = index === activeSlot
          const isActive = isCurrent && (isFocused || isAutofocusPending)
          return (
            <div key={index} className="contents">
              {separatorAfter === index ? (
                <span className="px-1 text-muted" aria-hidden="true">-</span>
              ) : null}
              <div
                data-active={isActive ? 'true' : undefined}
                data-current={isCurrent ? 'true' : undefined}
                data-disabled={disabled ? 'true' : undefined}
                data-filled={char ? 'true' : undefined}
                data-invalid={isInvalid ? 'true' : undefined}
                data-slot="input-otp-slot"
                className={slotClasses}
              >
                {char ? (
                  <div data-slot="input-otp-slot-value" className={slotValueClasses}>
                    {char}
                  </div>
                ) : null}
                {isActive && !char ? (
                  <div data-slot="input-otp-caret" className={caretClasses} />
                ) : null}
              </div>
            </div>
          )
        })}
      </div>
      <input
        {...props}
        ref={inputRef}
        data-input-otp
        name={props.name}
        defaultValue={currentValue}
        disabled={disabled}
        maxLength={separatorAfter && inputMode === 'text' ? length + 1 : length}
        pattern={pattern}
        inputMode={inputMode}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        aria-invalid={isInvalid || undefined}
        className={[
          'absolute inset-0 z-10 h-full w-full cursor-text border-0 bg-transparent text-transparent outline-none shadow-none [caret-color:transparent]',
          inputClassName,
        ].filter(Boolean).join(' ')}
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
      groupClassName={['gap-1', groupClassName].filter(Boolean).join(' ')}
      slotClassName={[
        'size-8 min-h-8 min-w-8 text-base sm:size-9 sm:min-h-9 sm:min-w-9',
        slotClassName,
      ]
        .filter(Boolean)
        .join(' ')}
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
