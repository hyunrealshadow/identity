import { Button } from '@identity/ui/components/button'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from '@identity/ui/components/input-group'
import { Check, Copy, Download, Printer } from 'lucide-react'
import { useState } from 'react'

interface RecoveryCodeToolsProps {
  codes: Array<string>
  copyLabel: string
  copiedLabel: string
  printLabel: string
  downloadLabel: string
}

interface RecoveryCodeListProps {
  codes: Array<string>
  copyLabel: string
  copiedLabel: string
}

export function RecoveryCodeList({ codes, copyLabel, copiedLabel }: RecoveryCodeListProps) {
  const [copiedIndex, setCopiedIndex] = useState<number>()

  async function copyCode(code: string, index: number) {
    try {
      await navigator.clipboard.writeText(code)
      setCopiedIndex(index)
      window.setTimeout(() => setCopiedIndex((current) => current === index ? undefined : current), 2000)
    } catch {
      // The read-only input remains selectable when clipboard access is unavailable.
    }
  }

  return (
    <div id="recovery-codes-sheet" className="grid gap-2 sm:grid-cols-2">
      {codes.map((code, index) => {
        const copied = copiedIndex === index
        return (
          <InputGroup key={`${code}-${index}`} className="bg-muted/50">
            <InputGroupInput
              readOnly
              value={code}
              aria-label={`${copyLabel} ${index + 1}`}
              className="font-mono"
            />
            <InputGroupAddon align="inline-end">
              <InputGroupButton
                size="icon-xs"
                aria-label={copied ? copiedLabel : copyLabel}
                onClick={() => void copyCode(code, index)}
              >
                {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
              </InputGroupButton>
            </InputGroupAddon>
          </InputGroup>
        )
      })}
    </div>
  )
}

/**
 * Copy-all and print affordances for the recovery-code sheet. Rendered inside
 * a `.js-only` gate; without JavaScript the native download form remains as
 * the portable-copy path.
 */
export function RecoveryCodeTools({ codes, copyLabel, copiedLabel, printLabel, downloadLabel }: RecoveryCodeToolsProps) {
  const [copied, setCopied] = useState(false)

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(codes.join('\n'))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API unavailable (permissions, insecure context): leave the
      // button in its idle state; the codes stay manually selectable.
    }
  }

  function download() {
    const blob = new Blob([`${codes.join('\n')}\n`], {
      type: 'text/plain;charset=utf-8',
    })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'identity-recovery-codes.txt'
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <Button type="button" size="sm" variant="outline" onClick={() => void copyAll()}>
        {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        {copied ? copiedLabel : copyLabel}
      </Button>
      <Button type="button" size="sm" variant="outline" onClick={() => window.print()}>
        <Printer aria-hidden="true" />
        {printLabel}
      </Button>
      <Button type="button" size="sm" variant="outline" onClick={download}>
        <Download aria-hidden="true" />
        {downloadLabel}
      </Button>
    </>
  )
}
