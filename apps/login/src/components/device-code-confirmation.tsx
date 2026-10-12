import { translate, type Locale } from '#/lib/i18n'

export function DeviceCodeConfirmation({ code, locale }: { code: string; locale: Locale }) {
  return (
    <section className="mb-6" aria-labelledby="device-code-title">
      <h2 id="device-code-title" className="text-sm font-medium">
        {translate(locale, 'deviceConfirmCodeTitle')}
      </h2>
      <p className="mt-1 text-xs leading-5 text-muted">
        {translate(locale, 'deviceConfirmCodeDescription')}
      </p>
      <code className="mt-3 block rounded-lg border border-border bg-surface-secondary px-3 py-2.5 text-center font-mono text-xl font-semibold leading-tight tracking-[0.12em] [overflow-wrap:anywhere] sm:text-2xl sm:tracking-[0.18em]">
        {code}
      </code>
    </section>
  )
}
