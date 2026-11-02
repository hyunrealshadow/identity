import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const schemaPath = resolve(here, '../../graphql/schema.graphql')
const outputPath = resolve(here, 'src/schema.ts')
const consolePackagePath = resolve(here, '../../apps/console/package.json')

async function loadGraphql() {
  try {
    return await import('graphql')
  } catch {
    const consoleRequire = createRequire(consolePackagePath)
    return consoleRequire('graphql')
  }
}

const graphql = await loadGraphql()
const {
  buildSchema,
  getNamedType,
  isInterfaceType,
  isObjectType,
  isUnionType,
  valueFromASTUntyped,
} = graphql

const AUTHENTICATION_VALUES = new Set([
  'SESSION',
  'AAL2',
  'RECENT',
  'RECENT_AAL2',
  'ACCOUNT_SECURITY',
])

function validAge(value, where, field) {
  if (value === undefined || value === null) return undefined
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${field} on ${where} must be a non-negative integer`)
  }
  return value
}

function normalizePolicy(raw, where) {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`@access policy on ${where} must be an input object`)
  }

  if (
    !Array.isArray(raw.scopes) ||
    !raw.scopes.every((scope) => typeof scope === 'string')
  ) {
    throw new Error(`@access policy.scopes on ${where} must be [String!]!`)
  }
  if (!AUTHENTICATION_VALUES.has(raw.authentication)) {
    throw new Error(`@access policy.authentication on ${where} is invalid`)
  }
  if (typeof raw.userOnly !== 'boolean') {
    throw new Error(`@access policy.userOnly on ${where} must be Boolean!`)
  }
  if (typeof raw.runtime !== 'boolean') {
    throw new Error(`@access policy.runtime on ${where} must be Boolean!`)
  }

  const policy = {
    scopes: [...raw.scopes],
    authentication: raw.authentication,
    userOnly: raw.userOnly,
    runtime: raw.runtime,
  }
  const maxAge = validAge(raw.maxAge, where, 'policy.maxAge')
  const elevatedMaxAge = validAge(
    raw.elevatedMaxAge,
    where,
    'policy.elevatedMaxAge',
  )
  if (maxAge !== undefined) policy.maxAge = maxAge
  if (elevatedMaxAge !== undefined) policy.elevatedMaxAge = elevatedMaxAge
  return policy
}

function accessPolicies(field, where) {
  const directives =
    field.astNode?.directives?.filter(
      (directive) => directive.name.value === 'access',
    ) ?? []

  return directives.map((directive) => {
    const argument = directive.arguments?.find(
      (entry) => entry.name.value === 'policy',
    )
    if (!argument) {
      throw new Error(`@access on ${where} is missing its policy argument`)
    }
    return normalizePolicy(valueFromASTUntyped(argument.value), where)
  })
}

export function parseSchemaMetadata(sdl) {
  const schema = buildSchema(sdl)
  const types = {}

  for (const type of Object.values(schema.getTypeMap())) {
    if (type.name.startsWith('__')) continue

    if (isObjectType(type) || isInterfaceType(type)) {
      const fields = {}
      const fieldMap = type.getFields()
      for (const fieldName of Object.keys(fieldMap).sort()) {
        const field = fieldMap[fieldName]
        fields[fieldName] = {
          name: field.name,
          returnType: getNamedType(field.type).name,
          policies: accessPolicies(field, `${type.name}.${field.name}`),
        }
      }

      types[type.name] = {
        kind: isInterfaceType(type) ? 'INTERFACE' : 'OBJECT',
        interfaces: isObjectType(type)
          ? type
              .getInterfaces()
              .map((entry) => entry.name)
              .sort()
          : [],
        possibleTypes: isInterfaceType(type)
          ? schema
              .getPossibleTypes(type)
              .map((entry) => entry.name)
              .sort()
          : [],
        fields,
      }
      continue
    }

    if (isUnionType(type)) {
      types[type.name] = {
        kind: 'UNION',
        interfaces: [],
        possibleTypes: type
          .getTypes()
          .map((entry) => entry.name)
          .sort(),
        fields: {},
      }
    }
  }

  const queryType = schema.getQueryType()
  if (!queryType) throw new Error('GraphQL schema has no query root')

  const mutationType = schema.getMutationType()
  const metadata = {
    queryTypeName: queryType.name,
    mutationTypeName: mutationType?.name ?? null,
    types: {},
  }
  for (const name of Object.keys(types).sort()) metadata.types[name] = types[name]

  for (const root of [queryType, mutationType]) {
    if (!root) continue
    const rootType = metadata.types[root.name]
    if (!rootType) throw new Error(`Root type ${root.name} is missing metadata`)
    for (const field of Object.values(rootType.fields)) {
      if (field.policies.length === 0) {
        throw new Error(
          `Root field ${root.name}.${field.name} is missing @access metadata`,
        )
      }
    }
  }

  return metadata
}

export function renderSchemaModule(metadata) {
  return `/* eslint-disable */
// Generated by packages/graphql-access/generator.mjs from graphql/schema.graphql.
// Do not edit this file by hand.
import type { SchemaMetadata } from './types'

export const schemaMetadata: SchemaMetadata = ${JSON.stringify(metadata, null, 2)}
`
}

export function generateSchemaSource(sdl) {
  return renderSchemaModule(parseSchemaMetadata(sdl))
}

async function main() {
  const sdl = await readFile(schemaPath, 'utf8')
  const expected = generateSchemaSource(sdl)

  if (process.argv.includes('--check')) {
    let actual = ''
    try {
      actual = await readFile(outputPath, 'utf8')
    } catch {
      actual = ''
    }
    if (actual !== expected) {
      console.error(
        'graphql-access schema metadata is stale; run packages/graphql-access/generator.mjs',
      )
      process.exitCode = 1
      return
    }
    console.log('graphql-access schema metadata is up to date')
    return
  }

  await mkdir(dirname(outputPath), { recursive: true })
  await writeFile(outputPath, expected)
  console.log(`Wrote ${outputPath}`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main()
}
