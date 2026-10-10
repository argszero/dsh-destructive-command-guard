/**
 * A command line can be catastrophic while containing no dangerous path.
 *
 * The reported incident is the clean example. An agent preparing a test fixture
 * wrote `$home = "<workspace>/out/fakehome"` and then
 * `Remove-Item $home -Recurse -Force`. In PowerShell variable names are
 * case-insensitive and the automatic variables are read-only, so `$home` *is*
 * `$HOME`: the assignment failed as a non-terminating error, `$ErrorActionPreference`
 * defaults to `Continue`, the deletion ran anyway, and it removed the operator's
 * real profile — SSH keys, credential stores, and the directory junctions the
 * harness itself keeps its data behind. The command contains no `C:\Users\…`,
 * no `~` and no `$env:USERPROFILE`; every path in it is a workspace path. What
 * makes it dangerous is a fact about the *language*, which is why neither a path
 * pattern nor a careful reading of the text catches it.
 *
 * That is the gap this plugin fills, and it fills it in the one place the harness
 * offers for deciding before a tool runs.
 *
 * ## Where it sits, and why there rather than at `ctx.tools.guard`
 *
 * `tools/pre-execute` is the documented interception point — *"Allow, deny,
 * cancel, or ask before dispatch"* — and a `deny` there short-circuits the
 * pipeline: the tool body never runs. The registry also offers
 * `ctx.tools.guard()`, a monotonic check that denies by returning a reason, and
 * it is emphatically **not** used here. Read from the registry's own pipeline, a
 * guard is consulted only once the waterfall has already resolved to `allow`
 * (`const denialReason = decision.kind === 'allow' ? this.guardReason(exec) : …`),
 * so a call that would prompt for approval is prompted *first* and refused
 * second — the operator is asked to authorise a command that is then rejected.
 * A listener in the waterfall refuses before the question is asked, and
 * `{ prepend: true }` keeps it ahead of other policy listeners for the same
 * reason.
 *
 * ## What it refuses, and what it deliberately does not
 *
 * Two rules, both anchored to a fact about the shell rather than to a guess about
 * intent: an **automatic-variable collision** (a read-only name assigned and then
 * used as a deletion operand, so the operand holds the runtime's value) and a
 * **protected location** (a recursive or forced deletion whose operand is a home
 * reference or a filesystem root). `src/policy.ts` states the reasoning.
 *
 * Just as deliberately, it does **not** refuse recursive forced deletion of a
 * variable — `rm -rf "$BUILD_DIR"` is ordinary — nor arbitrary paths that merely
 * look sensitive. A guard that refuses ordinary work is a guard that gets
 * unmounted, and an unmounted guard protects nothing. The residual coverage is
 * stated rather than implied; see the README's honest-boundaries section.
 *
 * The verdict is produced by a lexical scan, not a parser (`src/scan.ts` says
 * what it can and cannot read), and it **fails open**: an unexpected error in the
 * scan is logged and the call proceeds. A guard whose own bug could refuse every
 * tool call in a deployment is a worse failure than the one it prevents.
 *
 * @module @argszero/dsh-destructive-command-guard
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import { defaultConfig, normalizeConfig } from './config.ts'
import type { Config, Settings } from './config.ts'
import { inspect } from './policy.ts'
import { renderDenial } from './advice.ts'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'destructive-command-guard'

/**
 * The service this plugin reads. `tools` is required twice over: the listener is
 * dispatched through the tool registry's own waterfall, and the optional
 * inspection tool is registered on the same registry.
 */
export const inject = ['tools']

export type { Config, Settings, GuardMode } from './config.ts'
export { defaultConfig, normalizeConfig } from './config.ts'
export { inspect, locationOf, RESERVED_PATH_VARIABLES } from './policy.ts'
export type { Finding, RuleId, LocationShape, JudgeOptions } from './policy.ts'
export { findDeletions, readAssignments, splitStatements, variableName } from './scan.ts'
export type { Deletion, Statement, Token, Assignments } from './scan.ts'
export { renderDenial } from './advice.ts'

/** The command line a call is about to run, when it is one this guard inspects. */
function commandOf(exec: ToolExecution, settings: Settings): string | undefined {
  if (settings.onlyTools.length > 0 && !settings.onlyTools.includes(exec.name)) return undefined
  const args = exec.arguments
  if (typeof args !== 'object' || args === null) return undefined
  const command = (args as { command?: unknown }).command
  return typeof command === 'string' && command.trim() !== '' ? command : undefined
}

/** Whether the operator exempted this command from the guard. */
function isExempt(command: string, settings: Settings): boolean {
  return settings.exempt.some(entry => command.includes(entry))
}

/**
 * The denial for a call, or `undefined` when it is allowed.
 *
 * Every path out of this function is deliberate. A call the guard does not
 * inspect is allowed; an exempt command is allowed; a scan that throws is logged
 * and allowed, because the alternative — a plugin bug refusing every command in
 * the deployment — is the failure mode a guard must not have.
 * @param exec - the pending call.
 * @param settings - the resolved configuration.
 * @param onError - called with anything the scan threw.
 * @returns the reason to refuse, or `undefined`.
 */
function denyReason(
  exec: ToolExecution,
  settings: Settings,
  onError: (error: unknown) => void,
): string | undefined {
  const command = commandOf(exec, settings)
  if (command === undefined) return undefined
  if (isExempt(command, settings)) return undefined
  let findings
  try {
    findings = inspect(command, {
      reserved: settings.reserved,
      protectedPaths: settings.protectedPaths,
      home: settings.home,
      reservedCollision: settings.reservedCollision,
      homeTarget: settings.homeTarget,
    })
  } catch (error: unknown) {
    onError(error)
    return undefined
  }
  if (findings.length === 0) return undefined
  return renderDenial(findings, command, settings.maxReasonChars)
}

/**
 * The read-only inspection tool.
 *
 * It answers the question the rules are otherwise only visible through a
 * refusal, which is what makes `mode: 'report'` and the `exempt` list usable
 * without guessing: the same decision, on demand, without executing anything.
 * @param settings - the resolved configuration.
 * @returns the tool definition.
 */
function checkTool(settings: Settings) {
  return defineTool({
    name: 'destructive_command_check',
    description: 'Report whether destructive-command-guard would refuse a shell command, and why, '
      + 'without running it. Use it to check a command before calling bash/pwsh, or to find out '
      + 'which rule a command trips.',
    parameters: {
      command: {
        type: 'string',
        required: true,
        description: 'The shell command to check. It is not executed.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const command = typeof args.command === 'string' ? args.command : ''
      if (command.trim() === '') return 'destructive_command_check: the command argument is empty; nothing to check.'
      const findings = inspect(command, {
        reserved: settings.reserved,
        protectedPaths: settings.protectedPaths,
        home: settings.home,
        reservedCollision: settings.reservedCollision,
        homeTarget: settings.homeTarget,
      })
      if (findings.length === 0) {
        return isExempt(command, settings)
          ? 'ALLOWED (exempt): the command matches the exempt list, so the guard will not refuse it.'
          : 'ALLOWED: no rule matches this command.'
      }
      return `REFUSED (${settings.mode === 'report' ? 'report mode: logged, not refused' : 'enforce mode'}):\n\n`
        + renderDenial(findings, command, settings.maxReasonChars)
    },
  })
}

/**
 * Mount the guard.
 *
 * `config` is whatever a loader entry passed, or `undefined` when it passed
 * nothing, so the default lives here. It cannot live in an exported `Config`:
 * Cordis reads `Config['~standard'].validate` off a plugin's `Config`, and a
 * plain defaults object has no such property, so naming one there makes the mount
 * throw before this function is called.
 * @param ctx - the plugin context.
 * @param config - the plugin configuration.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const settings = normalizeConfig(config)
  if (settings.mode === 'off') return

  ctx.effect(() => {
    const disposed = ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
      const reason = denyReason(exec, settings, error => {
        ctx.logger.warn(`destructive-command-guard: scan failed, allowing the call: ${String(error)}`)
      })
      if (reason === undefined) return next()
      if (settings.mode === 'report') {
        ctx.logger.warn(`destructive-command-guard (report): would refuse ${exec.name}: ${reason}`)
        return next()
      }
      ctx.logger.warn(`destructive-command-guard: refused ${exec.name}: ${reason}`)
      return { kind: 'deny', reason }
    }, { prepend: true })

    const tool = settings.tool ? ctx.tools.register(checkTool(settings)) : undefined
    return () => {
      disposed()
      tool?.()
    }
  }, 'destructive-command-guard: refuse commands that collide with an automatic variable or target a protected location')
}

/**
 * The object a loader entry mounts: `vendor/loader` normalises a plugin module
 * with `exports.default ?? exports` and hands this to `ctx.plugin`, which reads
 * `Config['~standard'].validate` off it when it is present.
 *
 * `Config: defaultConfig` used to be exported here. `defaultConfig` is a plain
 * object rather than a schema, so the lookup found no `~standard` and every mount
 * of the installed package died with `TypeError: Cannot read properties of
 * undefined (reading 'validate')` before `apply` ran. The defaults reach a mount
 * through `apply(ctx, config = {})` instead, and the convention in this
 * repository's own packages is a real schema (`export const Config = z.object(…)`)
 * or no `Config` at all — never a plain object.
 */
export default { name, inject, apply }
