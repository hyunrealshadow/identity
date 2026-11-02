import { createFileRoute } from '@tanstack/react-router'

import { OverviewPage } from '#/modules/dashboard/pages/overview-page'

export const Route = createFileRoute('/_app/(dashboard)/')({
  staticData: { breadcrumbs: [{ label: 'overviewTitle', link: false }] },
  component: OverviewPage,
})
