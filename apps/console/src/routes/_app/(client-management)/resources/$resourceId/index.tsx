import { createFileRoute } from '@tanstack/react-router'
import { ResourceDetailPage } from '#/modules/client-management/resources/pages/resource-detail-page'
export const Route = createFileRoute(
  '/_app/(client-management)/resources/$resourceId/',
)({ component: ResourceDetailPage })
