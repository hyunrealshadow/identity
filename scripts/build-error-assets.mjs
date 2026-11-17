#!/usr/bin/env node
// Build the provider's server-rendered error page assets into assets/static:
// the Tailwind stylesheet and the Inter Variable files it references.
//
// Every output is named by its content hash (`error.<hash>.css`) so it can be
// cached permanently. `assets/static/manifest.json` maps each logical path to
// its current file; Identity reads it at startup for the `asset()` template
// function.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, parse } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(join(root, 'package.json'))
const staticDir = join(root, 'assets/static')

// 16 hex characters; the static route treats this shape as fingerprinted.
const contentHash = (bytes) => createHash('sha256').update(bytes).digest('hex').slice(0, 16)
const fingerprinted = (name, bytes) => {
  const { name: stem, ext } = parse(name)
  return `${stem}.${contentHash(bytes)}${ext}`
}

const manifest = {}
for (const dir of ['css', 'fonts']) {
  rmSync(join(staticDir, dir), { recursive: true, force: true })
  mkdirSync(join(staticDir, dir), { recursive: true })
}

const fontFiles = ['inter-latin-wght-normal.woff2', 'inter-latin-ext-wght-normal.woff2']
const fontSource = join(dirname(require.resolve('@fontsource-variable/inter/package.json')), 'files')
for (const file of fontFiles) {
  const bytes = readFileSync(join(fontSource, file))
  const name = fingerprinted(file, bytes)
  copyFileSync(join(fontSource, file), join(staticDir, 'fonts', name))
  manifest[`fonts/${file}`] = `fonts/${name}`
}

const compiled = join(tmpdir(), `identity-error-${process.pid}.css`)
try {
  execFileSync(
    'tailwindcss',
    ['-i', 'assets/styles/error.css', '-o', compiled, '--minify'],
    { cwd: root, stdio: 'inherit' },
  )
  let css = readFileSync(compiled, 'utf8')
  for (const file of fontFiles) {
    const reference = `../fonts/${file}`
    if (!css.includes(reference)) {
      throw new Error(`error.css no longer references ${reference}`)
    }
    css = css.replaceAll(reference, `../${manifest[`fonts/${file}`]}`)
  }
  const name = fingerprinted('error.css', css)
  writeFileSync(join(staticDir, 'css', name), css)
  manifest['css/error.css'] = `css/${name}`
} finally {
  rmSync(compiled, { force: true })
}

writeFileSync(join(staticDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
