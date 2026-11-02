import { spawnSync } from 'node:child_process'
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const catalog = process.argv.includes('--error-catalog')
const management = process.argv.includes('--management-catalog')
const args = ['run', '--quiet', '-p', 'identity-web', '--bin', 'identity-schema']
if (catalog) args.push('--', '--error-catalog')
if (management) args.push('--', '--management-catalog')
const result = spawnSync('cargo', args, {
  cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
})
if (result.status !== 0) {
  process.stderr.write(result.stderr || 'GraphQL schema export failed\n')
  process.exit(result.status ?? 1)
}
const filename = catalog ? 'error-catalog.json' : management ? 'management-scopes.json' : 'schema.graphql'
const path = new URL('../graphql/' + filename, import.meta.url)
if (process.argv.includes('--check')) {
  if (readFileSync(path, 'utf8') !== result.stdout) {
    process.stderr.write('graphql/' + filename + ' differs from the executable contract\n')
    process.exit(1)
  }
} else {
  mkdirSync(new URL('../graphql/', import.meta.url), { recursive: true })
  writeFileSync(path, result.stdout, 'utf8')
}
