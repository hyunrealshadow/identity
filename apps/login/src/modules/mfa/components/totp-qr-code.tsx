import { useEffect, useState } from 'react'

interface TotpQrCodeProps {
  label: string
  uri: string
}

export function TotpQrCode({ uri, label }: TotpQrCodeProps) {
  const [svg, setSvg] = useState<string>()

  useEffect(() => {
    let active = true
    setSvg(undefined)
    void import('qrcode')
      .then(({ default: QRCode }) => QRCode.toString(uri, {
        type: 'svg',
        margin: 0,
        errorCorrectionLevel: 'M',
        color: { dark: '#18181b', light: '#ffffff' },
      }))
      .then((value) => {
        if (active) setSvg(value)
      })
      .catch(() => {
        if (active) setSvg(undefined)
      })
    return () => {
      active = false
    }
  }, [uri])

  return svg
    ? <div className="account-qr" role="img" aria-label={label} dangerouslySetInnerHTML={{ __html: svg }} />
    : null
}
