import { createFileRoute } from '@tanstack/react-router'
import { EmailDeliveryPage } from '#/modules/instance/email/pages/email-delivery-page'
export const Route = createFileRoute('/_app/(instance)/email/')({
  staticData: {
    // The email route above contributes the leading crumbs.
    breadcrumbs: [{ label: 'emailTabDelivery' }],
  },
  component: EmailDeliveryPage,
})
