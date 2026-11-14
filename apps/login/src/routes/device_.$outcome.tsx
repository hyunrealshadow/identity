import { createFileRoute, notFound } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { decisionOutcome, DeviceOutcomePage } from '#/components/device-outcome'
import { requestLocale } from '#/lib/i18n.server'

interface DeviceOutcomeSearch {
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadDeviceOutcomePage = createServerFn({ method: 'GET' })
  .validator((data: { uiLocales?: string }) => data)
  .handler(({ data }) => ({
    locale: requestLocale(data.uiLocales?.split(' ')),
  }))

/**
 * Where the browser lands after approving or denying a device. It carries no
 * request state, so it stays valid after the device has redeemed its code.
 */
export const Route = createFileRoute('/device_/$outcome')({
  validateSearch: (search): DeviceOutcomeSearch => ({
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({ uiLocales: search.ui_locales }),
  loader: async ({ deps, params }) => {
    const outcome = decisionOutcome(params.outcome)
    if (!outcome) throw notFound()
    const page = await loadDeviceOutcomePage({ data: deps })
    return { ...page, outcome }
  },
  component: DeviceOutcomeRoute,
})

function DeviceOutcomeRoute() {
  const { locale, outcome } = Route.useLoaderData()
  return <DeviceOutcomePage locale={locale} outcome={outcome} />
}
