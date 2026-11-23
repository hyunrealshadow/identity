import { createFileRoute } from '@tanstack/react-router'
import { EmailTemplatePage } from '#/modules/instance/settings/pages/email-template-page'

function EmailTemplateRouteComponent() {
  const { kind } = Route.useParams()
  return <EmailTemplatePage slug={kind} />
}

export const Route = createFileRoute('/_app/(instance)/settings/email/templates/$kind')({
  staticData: {
    breadcrumbs: [
      { label: 'settingsTabEmail', to: '/settings/email' },
      { label: 'settingsEmailTemplateCrumb' },
    ],
  },
  component: EmailTemplateRouteComponent,
})
