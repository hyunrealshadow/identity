import { createFileRoute } from '@tanstack/react-router'

import { ALL_AUDIT_LOG } from '#/modules/instance/audit/lib/audit-logs'
import { normalizeAuditEventsSearch } from '#/modules/instance/audit/lib/audit-search'
import { AuditEventsPage } from '#/modules/instance/audit/pages/audit-events-page'

export const Route = createFileRoute('/_app/(audit)/audit-events/')({
  staticData: {
    breadcrumbs: [
      { label: 'navAudit', link: false },
      { label: ALL_AUDIT_LOG.nav, to: ALL_AUDIT_LOG.path },
    ],
  },
  validateSearch: normalizeAuditEventsSearch,
  component: () => <AuditEventsPage log={ALL_AUDIT_LOG} search={Route.useSearch()} />,
})
