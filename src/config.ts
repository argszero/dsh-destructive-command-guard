/**
 * Configuration, normalized once at mount.
 *
 * Every knob here answers a question an operator asks in the first hour of
 * running a guard: *what does it refuse* (`reservedCollision`, `homeTarget`,
 * `extraReserved`, `protectedPaths`), *which calls does it look at*
 * (`onlyTools`), *how do I re-enable one thing it got wrong* (`exempt`), *what
 * does it do when it fires* (`mode`), and *can I ask it first* (`tool`).
 *
 * The defaults are the strict-but-useful set: both rules on, the two shell tools,
 * enforcing. `report` exists because a guard that cannot be observed before it is
 * trusted is a guard that gets unmounted after its first surprise, and `off`
 * exists because "is this plugin responsible for the behaviour I am seeing" is a
 * question that should be answerable without uninstalling it.
 *
 * @module @argszero/dsh-destructive-command-guard/config
 */

import { homedir } from 'node:os'
import { dirname } from 'node:path'
import { RESERVED_PATH_VARIABLES } from './policy.ts'

/** What the guard does with a command it refuses. */
export type GuardMode = 'enforce' | 'report' | 'off'

/** The plugin configuration as a user writes it. */
export interface Config {
  /**
   * `enforce` (default) refuses the call with a reason. `report` logs the same
   * finding to the host log and lets the call run — the way to measure what the
   * guard would refuse without letting it refuse anything yet. `off` installs
   * nothing at all.
   */
  readonly mode?: GuardMode
  /** Apply the automatic-variable collision rule. */
  readonly reservedCollision?: boolean
  /** Apply the home-directory / filesystem-root operand rule. */
  readonly homeTarget?: boolean
  /** Extra variable names to treat as automatic, alongside the built-in set. */
  readonly extraReserved?: readonly string[]
  /** Extra absolute paths a deletion must not target. */
  readonly protectedPaths?: readonly string[]
  /**
   * The home directory to protect. Defaults to the running account's
   * (`os.homedir()`), which is the directory the command would actually remove
   * when the process runs as the same account.
   */
  readonly homeDirectory?: string
  /**
   * Commands containing any of these substrings are never refused. This is the
   * escape hatch for a deliberate deletion the rules read as an accident; it is
   * a substring match rather than a pattern so that what it exempts is legible
   * in a config file without a second mental model.
   */
  readonly exempt?: readonly string[]
  /**
   * The tool names to inspect. Defaults to the two shell tools. An empty list
   * inspects every tool whose `command` argument is a non-empty string, which is
   * how a deployment that renamed or wrapped its shell tool keeps the guard.
   */
  readonly onlyTools?: readonly string[]
  /** Register the `destructive_command_check` tool. */
  readonly tool?: boolean
  /** Inclusive bound for the denial reason delivered to the model. */
  readonly maxReasonChars?: number
}

/** The configuration with every default resolved. */
export interface Settings {
  readonly mode: GuardMode
  readonly reservedCollision: boolean
  readonly homeTarget: boolean
  readonly reserved: ReadonlySet<string>
  readonly protectedPaths: readonly string[]
  readonly home: string
  readonly exempt: readonly string[]
  readonly onlyTools: readonly string[]
  readonly tool: boolean
  readonly maxReasonChars: number
}

/**
 * The reference defaults: the value behind every absent knob.
 *
 * Deliberately **not** exported as the plugin's `Config`. Cordis validates a
 * mounted plugin's `Config` through `Config['~standard'].validate`, and a plain
 * defaults object has no `~standard`, so exporting one there makes the mount
 * throw before `apply` runs. The entry point exports `{ name, inject, apply }`
 * with no `Config`, and these defaults arrive through `apply(ctx, config = {})`.
 */
export const defaultConfig: Required<Config> = {
  mode: 'enforce',
  reservedCollision: true,
  homeTarget: true,
  extraReserved: [],
  protectedPaths: [],
  homeDirectory: '',
  exempt: [],
  onlyTools: ['bash', 'pwsh'],
  tool: true,
  maxReasonChars: 1200,
}

/** Read a boolean, falling back for anything that is not one. */
function boolean(value: boolean | undefined, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

/** Read a positive integer, falling back when the value is absent or unusable. */
function positiveInteger(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : fallback
}

/**
 * Read a list of non-empty strings, dropping anything else.
 *
 * The length bound is not decoration: these lists are matched against every
 * command, and an entry of unbounded length is a comparison that costs more than
 * the check it belongs to.
 * @param value - the configured list.
 * @param fallback - the default to use when the value is not a list.
 * @returns the usable entries, bounded.
 */
function strings(value: readonly string[] | undefined, fallback: readonly string[]): readonly string[] {
  if (!Array.isArray(value)) return fallback
  return value
    .filter((entry): entry is string => typeof entry === 'string' && entry.trim() !== '')
    .map(entry => entry.trim().slice(0, 512))
}

/**
 * Resolve a user configuration into the settings the guard runs with.
 *
 * The home directory is the one value that is *derived* rather than defaulted:
 * an operator who does not set it gets the account the plugin itself runs as, and
 * the protection follows the process rather than a guess about which account the
 * command line expects.
 * @param config - the configuration as mounted, possibly empty.
 * @returns every setting, with defaults applied.
 */
export function normalizeConfig(config: Config): Settings {
  const home = typeof config.homeDirectory === 'string' && config.homeDirectory.trim() !== ''
    ? config.homeDirectory.trim()
    : homedir()
  const protectedPaths = strings(config.protectedPaths, [])
  const reserved = new Set<string>(RESERVED_PATH_VARIABLES)
  for (const name of strings(config.extraReserved, [])) reserved.add(name.toLowerCase())
  return {
    mode: config.mode === 'off' || config.mode === 'report' ? config.mode : 'enforce',
    reservedCollision: boolean(config.reservedCollision, defaultConfig.reservedCollision),
    homeTarget: boolean(config.homeTarget, defaultConfig.homeTarget),
    reserved,
    // The directory the home sits in is protected too when it is not itself a
    // root: on every platform this repository runs on, removing it takes the
    // operator's own account with it.
    protectedPaths: [...new Set([...protectedPaths, dirname(home)].filter(path => path !== home && path !== '/' && path !== ''))],
    home,
    exempt: strings(config.exempt, []),
    onlyTools: strings(config.onlyTools, defaultConfig.onlyTools),
    tool: boolean(config.tool, defaultConfig.tool),
    maxReasonChars: positiveInteger(config.maxReasonChars, defaultConfig.maxReasonChars),
  }
}
