import { createFileRoute } from '@tanstack/react-router'

import { AuditEventsPage } from '#/modules/instance/audit/pages/audit-events-page'
import { normalizeAuditEventsSearch } from '#/modules/instance/audit/lib/audit-search'

export const Route = createFileRoute('/_app/(instance)/audit-events/')({
  staticData: {
    breadcrumbs: [
      { label: 'navInstance', link: false },
      { label: 'navAuditEvents', to: '/audit-events' },
    ],
  },
  validateSearch: normalizeAuditEventsSearch,
  component: () => <AuditEventsPage search={Route.useSearch()} />,
})
