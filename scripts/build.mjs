import { createHash } from 'node:crypto'
import { readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { build } from 'esbuild'

const PACKAGE_ID = '@dsh-external/dsh-redteam-model'

await rm('lib', { recursive: true, force: true })

// Host bundle: the DSH runtime provides every @deepseek-ai/* package.
await build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  outfile: 'lib/index.js',
  external: ['@deepseek-ai/*'],
})

// Web client bundle: react and the UI primitives come from the host module
// loader; only our own settings section code is bundled.
await build({
  entryPoints: ['src/client/index.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  outfile: 'lib/client.js',
  sourcemap: true,
  external: ['react', 'react/jsx-runtime', '@deepseek-ai/dsh-client-ui-primitives'],
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  banner: {
    js: [
      `window.__ModuleLoader__.load({ id: ${JSON.stringify(PACKAGE_ID)}, factory: (require) => {`,
      'var module = { exports: {} }; var exports = module.exports;',
    ].join('\n'),
  },
  footer: {
    js: 'return module.exports; } });',
  },
})

async function digestDirectory(directory) {
  const hash = createHash('sha256')

  async function visit(current, relative) {
    const entries = await readdir(current, { withFileTypes: true })
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)
    for (const entry of entries) {
      const absolute = path.join(current, entry.name)
      const child = relative === '' ? entry.name : `${relative}/${entry.name}`
      if (entry.isDirectory()) {
        hash.update(`d\0${child}\0`)
        await visit(absolute, child)
      } else if (entry.isFile()) {
        hash.update(`f\0${child}\0`)
        const content = await readFile(absolute)
        hash.update(Buffer.from(content.toString('latin1').replace(/\r\n/g, '\n'), 'latin1'))
        hash.update('\0')
      }
    }
  }

  await visit(directory, '')
  return `sha256:${hash.digest('hex')}`
}

async function buildModeDigests() {
  const modesRoot = path.resolve('modes')
  const entries = await readdir(modesRoot, { withFileTypes: true })
  const manifest = { schemaVersion: 1, modes: {} }
  for (const entry of entries.filter(item => item.isDirectory()).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const directory = path.join(modesRoot, entry.name)
    try {
      await stat(path.join(directory, 'preset.yml'))
    } catch {
      continue
    }
    manifest.modes[entry.name] = await digestDirectory(directory)
  }
  await writeFile('lib/mode-digests.json', `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
}

await buildModeDigests()

for (const file of ['lib/index.js', 'lib/client.js']) {
  const source = await readFile(file, 'utf8')
  await writeFile(file, source.replace(/[ \t]+$/gm, ''))
}

console.log(`[dsh-redteam-model] built Host and Web client bundles (${PACKAGE_ID})`)
