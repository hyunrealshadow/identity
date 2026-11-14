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
import { useEffect, useId, useMemo, useRef, useState } from 'react'

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
  hideLabel = false,
}: {
  value: string
  /** `automatic` marks the first resource chosen on the reader's behalf. */
  onChange: (id: string, options?: { automatic: boolean }) => void
  enabled?: boolean
  /** Toolbar use: the placeholder names the field; the label stays for assistive technology. */
  hideLabel?: boolean
}) {
  const t = useTranslator()
  const inputId = useId()
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [after, setAfter] = useState<string>()
  const [items, setItems] = useState<Resource[]>([])
  const [selected, setSelected] = useState<Resource>()
  // The automatic first choice runs when data arrives, not on every render.
  const onChangeRef = useRef(onChange)
  onChangeRef.current = onChange
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
      onChangeRef.current(next[0].id, { automatic: true })
    }
  }, [resources.data, after, value])
  // A value from outside (a link, reload or history) shows its resource name.
  useEffect(() => {
    if (!value || selected?.id === value) return
    const match = items.find((node) => node.id === value)
    if (match) {
      setSelected(match)
      setText(match.name)
    }
  }, [value, items, selected?.id])
  const options =
    selected && !items.some((node) => node.id === selected.id)
      ? [selected, ...items]
      : items
  return (
    <div className={hideLabel ? 'w-full sm:w-72' : 'w-full max-w-xl'}>
      <Field>
        <FieldLabel htmlFor={inputId} className={hideLabel ? 'sr-only' : undefined}>
          {t('rbacApiResource')}
        </FieldLabel>
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
