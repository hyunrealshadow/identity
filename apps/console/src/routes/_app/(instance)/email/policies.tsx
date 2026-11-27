import { createFileRoute } from '@tanstack/react-router'
import { EmailPolicyPage } from '#/modules/instance/email/pages/email-policy-page'

export const Route = createFileRoute('/_app/(instance)/email/policies')({
  component: EmailPolicyPage,
})
