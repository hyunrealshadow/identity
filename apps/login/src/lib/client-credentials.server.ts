import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'

export interface ClientCredentials {
  client_id: string
  client_secret: string
  application_url: string
}

const DEFAULT_CREDENTIALS_FILE = '.data/client-credentials.json'

function credentialsFile() {
  return resolve(
    process.env.IDENTITY_CLIENT_CREDENTIALS_FILE ?? DEFAULT_CREDENTIALS_FILE,
  )
}

function environmentCredentials(): ClientCredentials | undefined {
  const clientId = process.env.IDENTITY_CLIENT_ID
  const clientSecret = process.env.IDENTITY_CLIENT_SECRET
  if (!clientId && !clientSecret) return
  if (!clientId || !clientSecret) {
    throw new Error(
      'IDENTITY_CLIENT_ID and IDENTITY_CLIENT_SECRET must be configured together',
    )
  }
  return {
    client_id: clientId,
    client_secret: clientSecret,
    application_url: process.env.IDENTITY_PUBLIC_APP_URL ?? '',
  }
}

async function fileCredentials(): Promise<ClientCredentials | undefined> {
  try {
    const value = JSON.parse(
      await readFile(credentialsFile(), 'utf8'),
    ) as Partial<ClientCredentials>
    if (
      typeof value.client_id !== 'string' ||
      typeof value.client_secret !== 'string' ||
      typeof value.application_url !== 'string'
    ) {
      throw new Error('client credential file has an invalid structure')
    }
    return value as ClientCredentials
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      error.code === 'ENOENT'
    ) {
      return
    }
    throw error
  }
}

export async function loadClientCredentials() {
  const credentials = environmentCredentials() ?? (await fileCredentials())
  if (!credentials) {
    throw new Error(
      'Identity client credentials are unavailable; run installation or configure the client secret',
    )
  }
  return credentials
}

export async function persistClientCredentials(
  clientId: string,
  clientSecret: string,
  applicationUrl: string,
) {
  const credentials: ClientCredentials = {
    client_id: clientId,
    client_secret: clientSecret,
    application_url: normalizeApplicationUrl(applicationUrl),
  }
  await persistCredentials(credentials)
  return credentials
}

async function persistCredentials(credentials: ClientCredentials) {
  const path = credentialsFile()
  const temporaryPath = `${path}.${process.pid}.tmp`
  await mkdir(dirname(path), { recursive: true })
  await writeFile(
    temporaryPath,
    `${JSON.stringify(credentials, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600 },
  )
  await rename(temporaryPath, path)
  await chmod(path, 0o600).catch(() => undefined)
}

function normalizeApplicationUrl(value: string) {
  const url = new URL(value)
  if (
    url.protocol !== 'https:' ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      'The application URL must be an HTTPS origin without a path, query, or fragment',
    )
  }
  return url.toString().replace(/\/$/, '')
}
