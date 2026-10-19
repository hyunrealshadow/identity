import type { LoginClientDisplay } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import type { Locale } from '#/lib/i18n'

function webUrl(value?: string | null) {
  if (!value) return undefined
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined
  } catch {
    return undefined
  }
}

export function LoginClient({ client, locale }: { client?: LoginClientDisplay; locale: Locale }) {
  if (!client) return null
  const logo = webUrl(client.logo_uri)
  const policy = webUrl(client.policy_uri)
  const terms = webUrl(client.tos_uri)
  return (
    <div className="mb-6 space-y-3 text-center" data-login-client>
      {logo ? <img src={logo} alt={client.name} referrerPolicy="no-referrer" className="mx-auto h-12 max-w-full object-contain" /> : null}
      <p className="text-sm font-medium">{client.name}</p>
      {policy || terms ? (
        <div className="flex flex-wrap justify-center gap-4 text-sm">
          {policy ? <a href={policy} target="_blank" rel="noopener noreferrer" className="underline">{translate(locale, 'clientPrivacyPolicy')}</a> : null}
          {terms ? <a href={terms} target="_blank" rel="noopener noreferrer" className="underline">{translate(locale, 'clientTermsOfService')}</a> : null}
        </div>
      ) : null}
    </div>
  )
}
