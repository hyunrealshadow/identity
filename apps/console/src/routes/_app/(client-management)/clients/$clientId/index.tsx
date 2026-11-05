import { createFileRoute } from '@tanstack/react-router'
import { ClientDetailPage } from '#/modules/client-management/clients/pages/client-detail-page'
export const Route = createFileRoute('/_app/(client-management)/clients/$clientId/')({
  component: ClientDetailPage,
})
