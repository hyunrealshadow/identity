import { createFileRoute } from '@tanstack/react-router'

import { normalizeAuditEventsSearch } from '#/modules/instance/audit/lib/audit-search'
import { AuditEventsPage } from '#/modules/instance/audit/pages/audit-events-page'

export const Route = createFileRoute('/_app/(audit)/audit-events/')({
  staticData: {
    breadcrumbs: [
      { label: 'navAudit', link: false },
      { label: 'navAuditLog', to: '/audit-events' },
    ],
  },
  validateSearch: normalizeAuditEventsSearch,
  component: () => <AuditEventsPage search={Route.useSearch()} />,
})
