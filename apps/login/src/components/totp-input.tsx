import { inputOTPVariants } from '@heroui/react'
import type { InputHTMLAttributes } from 'react'
import { useCallback, useEffect, useRef, useState } from 'react'

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

type InternalSegmentedCodeInputProps = SegmentedCodeInputProps & {
  autoComplete: string
  inputMode: 'numeric' | 'text'
  length: number
  normalize: (value: string) => string
  pattern: string
  separatorAfter?: number
}

function normalizeTotp(value: string) {
  return value.replace(/\D/g, '').slice(0, 6)
}

function normalizeRecoveryCode(value: string) {
  return value.replace(/[^a-z0-9]/gi, '').toUpperCase().slice(0, 8)
}

/** A segmented code field backed by one stable native input. */
function SegmentedCodeInput({
  autoComplete,
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
}: InternalSegmentedCodeInputProps) {
  const [internalValue, setInternalValue] = useState(() => normalize(defaultValue))
  const [isFocused, setIsFocused] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const currentValue = value === undefined ? internalValue : normalize(value)
  const lastValueRef = useRef(currentValue)
  const slots = inputOTPVariants({ variant })

  const updateValue = useCallback(
    (nextValue: string) => {
      const normalized = normalize(nextValue)
      if (normalized === lastValueRef.current) return
      lastValueRef.current = normalized
      if (value === undefined) setInternalValue(normalized)
      onChange?.(normalized)
    },
    [normalize, onChange, value],
  )

  useEffect(() => {
    lastValueRef.current = currentValue
  }, [currentValue])

  useEffect(() => {
    const input = inputRef.current
    if (!input) return

    // Password managers may assign the native value directly.
    const handleNativeInput = () => updateValue(input.value)
    input.addEventListener('input', handleNativeInput)
    return () => input.removeEventListener('input', handleNativeInput)
  }, [updateValue])

  const activeSlot = Math.min(currentValue.length, length - 1)

  return (
    <div
      data-input-otp-container
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
          const isActive = isFocused && index === activeSlot
          return (
            <div key={index} className="contents">
              {separatorAfter === index ? (
                <span className="px-1 text-muted" aria-hidden="true">-</span>
              ) : null}
              <div
                data-active={isActive ? 'true' : undefined}
                data-disabled={disabled ? 'true' : undefined}
                data-filled={char ? 'true' : undefined}
                data-invalid={isInvalid ? 'true' : undefined}
                data-slot="input-otp-slot"
                className={slots.slot({ className: slotClassName })}
              >
                {char ? (
                  <div data-slot="input-otp-slot-value" className={slots.slotValue()}>
                    {char}
                  </div>
                ) : null}
                {isActive && !char ? (
                  <div data-slot="input-otp-caret" className={slots.caret()} />
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
        value={currentValue}
        disabled={disabled}
        maxLength={separatorAfter ? length + 1 : length}
        pattern={pattern}
        inputMode={inputMode}
        autoComplete={autoComplete}
        aria-invalid={isInvalid || undefined}
        className={[
          'absolute inset-0 z-10 h-full w-full cursor-text border-0 bg-transparent text-transparent outline-none shadow-none [caret-color:transparent]',
          inputClassName,
        ].filter(Boolean).join(' ')}
        onChange={(event) => updateValue(event.currentTarget.value)}
        onFocus={(event) => {
          setIsFocused(true)
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
      className={['px-6 sm:px-10', className].filter(Boolean).join(' ')}
      groupClassName={['gap-1 sm:gap-2', groupClassName]
        .filter(Boolean)
        .join(' ')}
      slotClassName={[
        'size-9 min-h-9 min-w-9 sm:size-10 sm:min-h-10 sm:min-w-10',
        slotClassName,
      ]
        .filter(Boolean)
        .join(' ')}
      length={6}
      normalize={normalizeTotp}
      inputMode="numeric"
      pattern="^\d+$"
      autoComplete="one-time-code"
    />
  )
}

export function RecoveryCodeInput(props: SegmentedCodeInputProps) {
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
      normalize={normalizeRecoveryCode}
      inputMode="text"
      pattern="^[A-Za-z0-9-]+$"
      autoComplete="off"
    />
  )
}
