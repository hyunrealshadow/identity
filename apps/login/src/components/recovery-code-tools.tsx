import { Button } from '@heroui/react'
import { Check, Copy, Download, Printer } from 'lucide-react'
import { useState } from 'react'

interface RecoveryCodeToolsProps {
  codes: Array<string>
  copyLabel: string
  copiedLabel: string
  printLabel: string
  downloadLabel: string
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
