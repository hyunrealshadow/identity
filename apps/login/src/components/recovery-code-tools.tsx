import { Button, InputGroup } from '@heroui/react'
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
          <InputGroup key={`${code}-${index}`} variant="secondary" fullWidth>
            <InputGroup.Input
              readOnly
              value={code}
              aria-label={`${copyLabel} ${index + 1}`}
              className="font-mono"
            />
            <InputGroup.Suffix className="pe-0">
              <Button
                type="button"
                isIconOnly
                size="sm"
                variant="ghost"
                aria-label={copied ? copiedLabel : copyLabel}
                title={copied ? copiedLabel : copyLabel}
                onPress={() => void copyCode(code, index)}
              >
                {copied ? <Check className="size-4" aria-hidden="true" /> : <Copy className="size-4" aria-hidden="true" />}
              </Button>
            </InputGroup.Suffix>
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
      <Button type="button" size="sm" variant="secondary" onPress={() => void copyAll()}>
        {copied ? <Check className="size-4" aria-hidden="true" /> : <Copy className="size-4" aria-hidden="true" />}
        {copied ? copiedLabel : copyLabel}
      </Button>
      <Button type="button" size="sm" variant="secondary" onPress={() => window.print()}>
        <Printer className="size-4" aria-hidden="true" />
        {printLabel}
      </Button>
      <Button type="button" size="sm" variant="secondary" onPress={download}>
        <Download className="size-4" aria-hidden="true" />
        {downloadLabel}
      </Button>
    </>
  )
}
