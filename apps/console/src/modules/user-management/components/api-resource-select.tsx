import { Button } from '@identity/ui/components/button'
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from '@identity/ui/components/combobox'
import { Field, FieldLabel } from '@identity/ui/components/field'
import { useEffect, useId, useMemo, useState } from 'react'

import {
  ConsoleResourceOptionsDocument,
  type ConsoleResourceOptionsQuery,
  type ConsoleResourceOptionsQueryVariables,
} from '#/generated/graphql'
import { useTranslator } from '#/lib/i18n'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

type Resource =
  ConsoleResourceOptionsQuery['resources']['edges'][number]['node']

export function ApiResourceSelect({
  value,
  onChange,
  enabled = true,
}: {
  value: string
  onChange: (id: string) => void
  enabled?: boolean
}) {
  const t = useTranslator()
  const inputId = useId()
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [after, setAfter] = useState<string>()
  const [items, setItems] = useState<Resource[]>([])
  const [selected, setSelected] = useState<Resource>()
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const next = text === selected?.name ? '' : text.trim()
      if (query !== next) {
        setQuery(next)
        setAfter(undefined)
        setItems([])
      }
    }, 250)
    return () => window.clearTimeout(timer)
  }, [text, selected?.name, query])
  const variables = useMemo(
    () =>
      enabled ? { first: 20, after, filter: query ? { query } : {} } : null,
    [enabled, after, query],
  )
  const resources = useConsoleQuery<
    ConsoleResourceOptionsQuery,
    ConsoleResourceOptionsQueryVariables
  >(
    ConsoleResourceOptionsDocument,
    variables,
    enabled,
    'missing_resource_connection',
  )
  useEffect(() => {
    if (!resources.data) return
    const next = resources.data.resources.edges.map((edge) => edge.node)
    setItems((current) =>
      after
        ? [
            ...new Map(
              [...current, ...next].map((node) => [node.id, node]),
            ).values(),
          ]
        : next,
    )
    if (!value && next[0]) {
      setSelected(next[0])
      setText(next[0].name)
      onChange(next[0].id)
    }
  }, [resources.data, after, value, onChange])
  const options =
    selected && !items.some((node) => node.id === selected.id)
      ? [selected, ...items]
      : items
  return (
    <div className="w-full max-w-xl">
      <Field>
        <FieldLabel htmlFor={inputId}>{t('rbacApiResource')}</FieldLabel>
        <Combobox<Resource>
          items={options}
          value={selected ?? null}
          inputValue={text}
          onInputValueChange={setText}
          itemToStringLabel={(node) => node.name}
          itemToStringValue={(node) => node.id}
          isItemEqualToValue={(node, current) => node.id === current.id}
          disabled={!enabled}
          onValueChange={(node) => {
            if (!node) return
            setSelected(node)
            setText(node.name)
            onChange(node.id)
          }}
        >
          <ComboboxInput
            id={inputId}
            placeholder={t('rbacSearchApi')}
            disabled={!enabled}
          />
          <ComboboxContent className="max-w-[calc(100vw-2rem)]">
            <ComboboxEmpty>
              {resources.status === 'loading'
                ? t('loading')
                : t('rbacNoResources')}
            </ComboboxEmpty>
            <ComboboxList>
              {(node: Resource) => (
                <ComboboxItem key={node.id} value={node}>
                  <div className="min-w-0">
                    <p className="truncate font-medium">{node.name}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {node.uri}
                    </p>
                  </div>
                </ComboboxItem>
              )}
            </ComboboxList>
            {resources.data?.resources.pageInfo.hasNextPage ? (
              <div className="p-1">
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={resources.status === 'loading'}
                  onClick={() =>
                    setAfter(
                      resources.data?.resources.pageInfo.endCursor ??
                        undefined,
                    )
                  }
                >
                  {t('rbacLoadMore')}
                </Button>
              </div>
            ) : null}
            {resources.status === 'error' ? (
              <div className="p-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => void resources.refresh()}
                >
                  {t('retry')}
                </Button>
              </div>
            ) : null}
          </ComboboxContent>
        </Combobox>
      </Field>
    </div>
  )
}
