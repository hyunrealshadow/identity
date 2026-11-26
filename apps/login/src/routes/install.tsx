import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'

import { cachedInstallationStatus } from '#/lib/installation-status.server'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { submitInstallPost } from '#/modules/install/lib/install-route.server'
import {
  InstallPageView,
  type InstallSearch,
} from '#/modules/install/pages/install-page'

const visibleInstallFields = new Set([
  'domain',
  'application_url',
  'console_url',
  'username',
  'email',
  'password',
  'confirm_password',
  'signing_algorithm',
])

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadInstallPage = createServerFn({ method: 'GET' }).handler(async () => {
  const flash = consumeFormFlash('/install')
  const hasUnmappedFieldError = Object.keys(flash?.fields ?? {}).some(
    (field) => !visibleInstallFields.has(field),
  )
  const url = new URL(getRequest().url)
  url.protocol = 'https:'
  const development = process.env.NODE_ENV === 'development'
  const status = await cachedInstallationStatus()
  return {
    signingAlgorithms: status.signing_algorithms ?? [],
    // Draft defaults only: submitted addresses are validated and persisted by Identity.
    defaults: {
      domain: development ? 'https://localhost:5150' : url.origin,
      application_url: development ? 'https://localhost:3000' : url.origin,
      console_url: development ? 'https://localhost:3100' : url.origin,
    },
    locale: requestLocale(),
    error:
      flash?.field || (flash?.fields && !hasUnmappedFieldError)
        ? undefined
        : flash?.message,
    fieldErrors: {
      ...(flash?.fields ?? {}),
      ...(flash?.field && flash.message ? { [flash.field]: flash.message } : {}),
    },
    formValues: flash?.values ?? {},
  }
})

export const Route = createFileRoute('/install')({
  validateSearch: (search): InstallSearch => ({
    error: optionalString(search.error),
    username: optionalString(search.username),
    email: optionalString(search.email),
    domain: optionalString(search.domain),
    application_url: optionalString(search.application_url),
    console_url: optionalString(search.console_url),
  }),
  loader: () => loadInstallPage(),
  server: {
    handlers: {
      POST: ({ request }) => submitInstallPost(request),
    },
  },
  component: InstallRoute,
})

function InstallRoute() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  return <InstallPageView data={data} search={search} />
}
