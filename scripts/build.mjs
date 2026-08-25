import { rm, readFile, writeFile } from 'node:fs/promises'
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

for (const file of ['lib/index.js', 'lib/client.js']) {
  const source = await readFile(file, 'utf8')
  await writeFile(file, source.replace(/[ \t]+$/gm, ''))
}

console.log(`[dsh-redteam-model] built Host and Web client bundles (${PACKAGE_ID})`)
