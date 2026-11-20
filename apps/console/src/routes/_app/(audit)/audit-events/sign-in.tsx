import { createFileRoute } from '@tanstack/react-router'

import { AUDIT_CATEGORY_LOGS } from '#/modules/instance/audit/lib/audit-logs'
import { normalizeAuditEventsSearch } from '#/modules/instance/audit/lib/audit-search'
import { AuditEventsPage } from '#/modules/instance/audit/pages/audit-events-page'

const log = AUDIT_CATEGORY_LOGS.SIGN_IN

export const Route = createFileRoute('/_app/(audit)/audit-events/sign-in')({
  staticData: {
    breadcrumbs: [
      { label: 'navAudit', link: false },
      { label: log.nav, to: log.path },
    ],
  },
  validateSearch: normalizeAuditEventsSearch,
  component: () => <AuditEventsPage log={log} search={Route.useSearch()} />,
})
