/**
 * Pure preset-composition rewriting for deployed copies.
 *
 * The packaged `agent.cordis.yml` rows reference plugins by bare package name,
 * which ties their resolvability to the harness's composition base:
 * - `@dsh-external/*` rows resolve only when that base can walk up into the
 *   profile tree (true for the CLI web host, false for a packaged desktop
 *   host whose base lives inside the app bundle);
 * - the workflow-engine row must name whichever engine package the running
 *   harness actually ships (dsh-workflow-ptc on newer hosts,
 *   dsh-workflow-worker-thread on older ones — the two configs are identical).
 *
 * Neither fact is knowable in the source tree, so deployment copies are
 * rewritten — never the source tree. This module holds the pure text
 * transform: it maps composition text plus pre-resolved decisions to new
 * composition text, touching no files, so the rewrite stays unit-testable and
 * everything outside the touched rows stays byte-identical. Filesystem glue
 * (probing, path resolution, writing) lives in the manager.
 */

/**
 * Bump when the rewrite logic changes in a way deployed copies must replay.
 *
 * 2: the deployed-entry map is resolved from the collection's own `plugins/`
 * tree as well as the profile's `@dsh-external` links. A deploy that ran
 * before pnpm had created those links (the install path returns before it
 * links them) left bare package-name rows that revision 1 still counted as
 * current, so every such copy has to be replayed once.
 */
export const NORMALIZER_VERSION = 2

export const ENGINE_PACKAGES = {
  ptc: { id: 'workflow-ptc', name: '@deepseek-ai/dsh-workflow-ptc' },
  worker: { id: 'workflow-worker-thread', name: '@deepseek-ai/dsh-workflow-worker-thread' },
} as const

export type EngineFlavor = keyof typeof ENGINE_PACKAGES

const ENGINE_COMMENT = [
  '# 工作流执行引擎行：源树默认按新宿主声明；部署副本由安装器按运行宿主',
  '# 实际提供的引擎包改写（新宿主 dsh-workflow-ptc / 旧宿主 dsh-workflow-worker-thread，config 兼容）。',
]

export interface RewriteDecisions {
  /**
   * Engine row target for the copy: the package the running harness ships.
   * `undefined` leaves the engine row exactly as authored.
   */
  readonly engine?: { readonly id: string; readonly name: string }
  /**
   * Deployed-entry map for `@dsh-external/*` rows: package directory name to
   * the `file:` URL its entry file should be named by. Packages absent from
   * the map keep their bare package-name row.
   */
  readonly entries: Readonly<Record<string, string>>
}

export interface RewriteResult {
  /** The rewritten composition text (identical to the input when unchanged). */
  readonly text: string
  readonly changed: boolean
  readonly notes: readonly string[]
}

const ENGINE_ID_LINE = /^(\s*)- id: workflow-(ptc|worker-thread)\s*$/
const NAME_LINE = /^(\s*)name: '([^']+)'\s*$/
const EXTERNAL_NAME = /^@dsh-external\/([a-z0-9-]+)$/

/** Rewrite one composition's text. Pure: same input, same output, no IO. */
export function rewriteCompositionText(text: string, decisions: RewriteDecisions): RewriteResult {
  const lines = text.split('\n')
  const notes: string[] = []
  const entries: Readonly<Record<string, string>> = decisions.entries ?? {}

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ''
    const engineMatch = ENGINE_ID_LINE[Symbol.match](line)
    if (engineMatch !== null && decisions.engine !== undefined) {
      const target = decisions.engine
      const current = engineMatch[2] === 'ptc' ? ENGINE_PACKAGES.ptc : ENGINE_PACKAGES.worker
      const engineIndent = engineMatch[1] ?? ''
      const nameLine = NAME_LINE[Symbol.match](lines[index + 1] ?? '')
      if (nameLine === null || nameLine[2] !== current.name) continue
      // Replace the contiguous comment block sitting directly above the row.
      let first = index
      while (first > 0 && (lines[first - 1] ?? '').trimStart().startsWith('#')) first -= 1
      const replacement = [
        ...ENGINE_COMMENT.map(comment => `${engineIndent}${comment}`),
        `${engineIndent}- id: ${target.id}`,
        `${nameLine[1] ?? ''}name: '${target.name}'`,
      ]
      lines.splice(first, index + 2 - first, ...replacement)
      index = first + replacement.length - 1
      if (current.name !== target.name) notes.push(`engine row rewritten to ${target.name}`)
      continue
    }

    const externalMatch = NAME_LINE[Symbol.match](line)
    if (externalMatch === null) continue
    const external = EXTERNAL_NAME[Symbol.match](externalMatch[2] ?? '')
    if (external === null) continue
    const dirName = external[1] ?? ''
    if (dirName === '') continue
    const url = entries[dirName]
    if (url === undefined) {
      notes.push(`@dsh-external/${dirName} not present under the profile; row left as authored`)
      continue
    }
    lines[index] = `${externalMatch[1] ?? ''}name: '${url}'`
    notes.push(`@dsh-external/${dirName} rewritten to file: row`)
  }

  const updated = lines.join('\n')
  return { text: updated, changed: updated !== text, notes }
}
