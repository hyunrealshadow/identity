import { createFileRoute } from '@tanstack/react-router'
import { EmailDeliveryPage } from '#/modules/instance/email/pages/email-delivery-page'
export const Route = createFileRoute('/_app/(instance)/email/')({
  component: EmailDeliveryPage,
})
