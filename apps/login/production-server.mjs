import { readFileSync } from 'node:fs'

const certificateFile = process.env.NITRO_SSL_CERT_FILE
const privateKeyFile = process.env.NITRO_SSL_KEY_FILE

if (Boolean(certificateFile) !== Boolean(privateKeyFile)) {
  throw new Error(
    'NITRO_SSL_CERT_FILE and NITRO_SSL_KEY_FILE must be configured together',
  )
}

if (certificateFile && privateKeyFile) {
  process.env.NITRO_SSL_CERT = readFileSync(certificateFile, 'utf8')
  process.env.NITRO_SSL_KEY = readFileSync(privateKeyFile, 'utf8')
}

const certificate = process.env.NITRO_SSL_CERT
const privateKey = process.env.NITRO_SSL_KEY
if (Boolean(certificate) !== Boolean(privateKey)) {
  throw new Error('NITRO_SSL_CERT and NITRO_SSL_KEY must be configured together')
}

process.env.IDENTITY_REQUIRE_UPSTREAM_HTTPS ??= certificate ? 'false' : 'true'

await import('./.output/server/index.mjs')
