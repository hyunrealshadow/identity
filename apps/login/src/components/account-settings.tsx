import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@identity/ui/components/card'

import { TextField } from '#/components/text-field'

export function PageHeading({ title, description }: { title: string; description: string }) {
  return <div className="mb-6"><h1 className="text-2xl font-semibold tracking-tight">{title}</h1><p className="mt-1.5 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p></div>
}

export function SettingsCard({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return <Card className="account-card gap-0 py-0"><CardHeader className="border-b px-5 py-4 [.border-b]:pb-4"><CardTitle className="text-sm font-semibold">{title}</CardTitle>{description ? <CardDescription className="leading-5">{description}</CardDescription> : null}</CardHeader><CardContent className="p-5">{children}</CardContent></Card>
}

export function SettingsRow({ title, description, detail, action }: { title: string; description?: string; detail?: React.ReactNode; action: React.ReactNode }) {
  return <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><p className="text-sm font-medium">{title}</p>{description ? <p className="mt-1 text-sm leading-5 text-muted-foreground">{description}</p> : null}{detail ? <div className="mt-2 text-xs font-medium text-muted-foreground">{detail}</div> : null}</div><div className="shrink-0">{action}</div></div>
}

export function ProfileField({ name, label, value, error, required = false, type }: { name: string; label: string; value?: string; error?: string; required?: boolean; type?: string }) {
  return <TextField required={required} name={name} label={label} error={error} defaultValue={value ?? ''} type={type} />
}

export function PasswordField({ name, label, error }: { name: string; label: string; error?: string }) {
  return <TextField required name={name} label={label} error={error} type="password" autoComplete="new-password" />
}
