import { Card, FieldError, Input, Label, TextField } from '@heroui/react'

export function PageHeading({ title, description }: { title: string; description: string }) {
  return <div className="mb-6"><h1 className="text-2xl font-semibold tracking-tight">{title}</h1><p className="mt-1.5 max-w-2xl text-sm leading-6 text-muted">{description}</p></div>
}

export function SettingsCard({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return <Card className="account-card overflow-hidden border border-border"><Card.Header className="border-b border-separator px-5 py-4"><Card.Title className="text-sm font-semibold">{title}</Card.Title>{description ? <Card.Description className="mt-1 text-sm leading-5">{description}</Card.Description> : null}</Card.Header><Card.Content className="p-5">{children}</Card.Content></Card>
}

export function SettingsRow({ title, description, detail, action }: { title: string; description?: string; detail?: React.ReactNode; action: React.ReactNode }) {
  return <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><p className="text-sm font-medium">{title}</p>{description ? <p className="mt-1 text-sm leading-5 text-muted">{description}</p> : null}{detail ? <div className="mt-2 text-xs font-medium text-muted">{detail}</div> : null}</div><div className="shrink-0">{action}</div></div>
}

export function ProfileField({ name, label, value, error, required = false, type }: { name: string; label: string; value?: string; error?: string; required?: boolean; type?: string }) {
  return <TextField isRequired={required} fullWidth isInvalid={Boolean(error)} name={name}><Label>{label}</Label><Input type={type} defaultValue={value} /><FieldError>{error}</FieldError></TextField>
}

export function PasswordField({ name, label, error }: { name: string; label: string; error?: string }) {
  return <TextField isRequired fullWidth isInvalid={Boolean(error)} name={name}><Label>{label}</Label><Input type="password" autoComplete="new-password" /><FieldError>{error}</FieldError></TextField>
}
