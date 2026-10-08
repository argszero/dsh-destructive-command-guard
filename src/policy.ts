/**
 * The two rules, and the reasons they are the two.
 *
 * A guard that decides before a command runs has to earn its refusals, because
 * every false one teaches the operator to unmount it and every missed one is the
 * incident it was written for. Both rules below are therefore anchored to a fact
 * about the *language*, not to a guess about intent:
 *
 * **`reserved-collision`** — PowerShell variable names are case-insensitive and
 * its automatic variables are read-only. `$home = "…"` therefore does not create
 * a variable: the assignment fails as a *non-terminating* error, and with
 * `$ErrorActionPreference` at its default `Continue` the statement after it runs
 * anyway — with `$home` still holding the real home directory. Any command that
 * assigns one of those names and then uses it as a deletion operand is deleting
 * something other than what it says, and no path-shaped check can see it because
 * the literal path in the command is the harmless one.
 *
 * **`home-target`** — a recursive or forced deletion whose operand *is* a home
 * reference (`$HOME`, `$home`, `~`, `$env:USERPROFILE`, `%USERPROFILE%`) or a
 * filesystem root. This needs no collision to be catastrophic, and it is read
 * from the operand directly rather than from the surrounding text.
 *
 * The two overlap on the reported incident — `Remove-Item $home -Recurse -Force`
 * trips both — which is the point: each covers cases the other cannot, and the
 * overlap is reported as one denial with both reasons.
 *
 * Everything else is deliberately *not* a rule. A recursive forced deletion of a
 * variable (`rm -rf "$BUILD_DIR"`) is one of the most ordinary things a command
 * line does; refusing it would make the guard unusable, so only operands that are
 * home references or roots are refused.
 *
 * @module @argszero/dsh-destructive-command-guard/policy
 */

import { findDeletions, readAssignments, variableName } from './scan.ts'

/** The rules this guard can apply, named so a denial can say which one fired. */
export type RuleId = 'reserved-collision' | 'home-target'

/** One refusal, with the facts that produced it. */
export interface Finding {
  /** Which rule fired. */
  readonly rule: RuleId
  /** The delete verb as written, lowercased. */
  readonly verb: string
  /** The operand that tripped the rule, as written. */
  readonly target: string
  /** The deletion was recursive. */
  readonly recursive: boolean
  /** The deletion was forced. */
  readonly force: boolean
  /** For `reserved-collision`: the automatic variable name that collided. */
  readonly name?: string
  /** For `home-target`: how the operand reads as a critical location. */
  readonly shape?: LocationShape
}

/**
 * How an operand reads as a place that must not be deleted.
 *
 * `home` is the directory itself; `home-contents` is everything directly under
 * it (`~/*`), which is no less destructive and textually distinct; `root` is a
 * filesystem root; `protected` is an absolute path the operator listed.
 */
export type LocationShape = 'home' | 'home-contents' | 'root' | 'protected'

/**
 * The PowerShell automatic variables that hold a **path**.
 *
 * Scoped to paths on purpose. The automatic set also contains behavioural
 * settings, and `$ErrorActionPreference = 'Stop'` immediately before a
 * deliberate cleanup is an ordinary and correct thing to write — a guard that
 * refused it would be refusing the *fix* for the bug it exists to report.
 */
export const RESERVED_PATH_VARIABLES: readonly string[] = [
  'home', 'pshome', 'pwd', 'psscriptroot', 'pscommandpath', 'profile',
  'myinvocation', 'executioncontext',
]

/** `~`, `$HOME`, `$home`, `${HOME}`, `$env:USERPROFILE`, `%USERPROFILE%`. */
const HOME_REFERENCE = /^(?:~|\$(?:\{)?(?:env:)?(?:home|userprofile)(?:\})?|%userprofile%)$/i
/** The same, immediately followed by a wildcard: everything inside the home. */
const HOME_CONTENTS = /^(?:~|\$(?:\{)?(?:env:)?(?:home|userprofile)(?:\})?|%userprofile%)[\\/]\*$/i
/** `$env:SystemDrive`, `${env:SystemDrive}`. */
const SYSTEM_DRIVE = /^\$(?:\{)?env:systemdrive(?:\})?$/i
/** A drive root: `C:`, `C:\`, `C:/`. */
const DRIVE_ROOT = /^[A-Za-z]:[\\/]*$/
/** A filesystem root in either separator convention, including `\\?\C:\`. */
const FILESYSTEM_ROOT = /^(?:[\\/]+|\\\\\?\\[A-Za-z]:[\\/]*)$/

/**
 * Normalise a path for comparison: separators unified, trailing ones dropped.
 *
 * Dropping the trailing separator is what makes `C:\Users\me\` and `C:\Users\me`
 * the same place — which they are, and which a comparison that did not do this
 * would answer as "two paths, one of which is not the home directory".
 * @param value - the path as written.
 * @returns the comparable form.
 */
function normalizePath(value: string): string {
  return value.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
}

/** Every fact a location reading needs. */
export interface LocationOptions {
  /** The home directory, as an absolute path. */
  readonly home: string
  /** Absolute paths that must not be deleted besides the home directory. */
  readonly protectedPaths: readonly string[]
  /**
   * Variable names the command assigned with a spelling that *works*, so a
   * lowercase operand naming one is the author's value rather than the
   * runtime's. See {@link ./scan.ts} `Assignments`.
   */
  readonly shadowed: ReadonlySet<string>
}

/**
 * Read an operand as a location that must not be deleted.
 *
 * The variable is consulted before the literal: `$home` is answered from the
 * name alone, because the name is what decides which value PowerShell will hand
 * the deletion — the literal path the command also contains is the one the
 * author meant and the one that does not matter.
 * @param target - the operand as written.
 * @param options - the home directory and the names the command shadowed.
 * @returns the shape, or `undefined` when the operand is an ordinary path.
 */
export function locationOf(target: string, options: LocationOptions): LocationShape | undefined {
  const text = target.trim()
  if (text === '') return undefined
  if (HOME_CONTENTS.test(text)) return 'home-contents'
  const bare = text.replace(/[\\/]+$/, '')
  if (HOME_REFERENCE.test(text) || (bare !== '' && HOME_REFERENCE.test(bare))) {
    const name = variableName(bare)
    // `$home` set by a spelling that works is the author's own variable; `$HOME`
    // is the same name, and the same question, one case apart.
    if (name !== undefined && options.shadowed.has(name)) return undefined
    return 'home'
  }
  if (FILESYSTEM_ROOT.test(text) || DRIVE_ROOT.test(text) || SYSTEM_DRIVE.test(text)) return 'root'
  const normalized = normalizePath(text)
  if (normalized === '') return undefined
  if (normalized === normalizePath(options.home)) return 'home'
  for (const candidate of options.protectedPaths) {
    if (normalized === normalizePath(candidate)) return 'protected'
  }
  return undefined
}

/** Everything the rules need to judge one command line. */
export interface JudgeOptions extends Omit<LocationOptions, 'shadowed'> {
  /** The reserved names to treat as automatic, lowercased. */
  readonly reserved: ReadonlySet<string>
  /** Apply the collision rule. */
  readonly reservedCollision: boolean
  /** Apply the home/root operand rule. */
  readonly homeTarget: boolean
}

/**
 * Decide whether a command line is one this guard refuses, and why.
 *
 * Both rules read the *same* parsed deletions, so a command that trips both
 * produces both findings and one denial. Deletions carrying `-WhatIf` are
 * excluded from both: a statement that removes nothing is not the destructive
 * step, and refusing it would refuse the safe way to rehearse the command.
 * @param command - the command line as the caller wrote it.
 * @param options - the rules to apply and the facts they need.
 * @returns every finding, in rule order; empty when the command is allowed.
 */
export function inspect(command: string, options: JudgeOptions): Finding[] {
  const deletions = findDeletions(command)
  if (deletions.length === 0) return []
  const { powershell, plain } = readAssignments(command)
  const findings: Finding[] = []

  if (options.reservedCollision) {
    const collided = [...powershell].filter(name => options.reserved.has(name))
    if (collided.length > 0) {
      for (const deletion of deletions) {
        if (deletion.dry) continue
        for (const target of deletion.targets) {
          const name = variableName(target)
          if (name === undefined || !collided.includes(name)) continue
          findings.push({
            rule: 'reserved-collision',
            verb: deletion.verb,
            target,
            recursive: deletion.recursive,
            force: deletion.force,
            name,
          })
        }
      }
    }
  }

  if (options.homeTarget) {
    for (const deletion of deletions) {
      // A deletion that removes nothing cannot destroy anything, and neither can
      // one that was never asked to be recursive or forced: a bare `rm $path` is
      // an ordinary operand, while `rm -rf $path` is the shape that takes a tree
      // with it.
      if (deletion.dry || (!deletion.recursive && !deletion.force)) continue
      for (const target of deletion.targets) {
        // The shadow set is handed to the reading itself, because only the
        // *variable* form consults it: a literal path that equals the home
        // directory is that directory no matter what the line assigned.
        const shape = locationOf(target, { ...options, shadowed: plain })
        if (shape === undefined) continue
        findings.push({
          rule: 'home-target',
          verb: deletion.verb,
          target,
          recursive: deletion.recursive,
          force: deletion.force,
          shape,
        })
      }
    }
  }

  return findings
}
