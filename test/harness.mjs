/**
 * The integration harness: a REAL cordis context, the REAL `ToolRuntime` from
 * `@deepseek-ai/dsh-tools`, and REAL tool definitions registered on it.
 *
 * Nothing about the seam is simulated. The plugin listens on
 * `tools/pre-execute`; this harness dispatches through `ctx.tools.execute()`,
 * which is the registry's own public entry point, so the pipeline under test —
 * the waterfall, the `deny` short-circuit, the normalized error result — is the
 * shipped one. The only fabricated article is the tool *body*, which records
 * that it ran and returns a canned value; that is what lets a test assert the
 * property the whole plugin rests on, that a refused call never reaches the body.
 *
 * `test/guard.spec.mjs` also runs the same call with the plugin absent, so every
 * refusal is measured against the same command *succeeding* when nothing is
 * mounted. A control arm is what turns "the result was an error" into "the plugin
 * caused the error".
 *
 * @module test/harness
 */

import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import * as plugin from '../lib/index.js'

/** The neutral signal every fabricated call carries. */
export const SIGNAL = new AbortController().signal

/**
 * Mount a real context with a real tool registry, and by default this plugin.
 *
 * @param spec - `plugin: false` mounts everything except this plugin (the control
 *   arm); `config` is the plugin's configuration; `tools` names the shell tools
 *   to register.
 * @returns the context, the record of every body that ran, and the captured log.
 */
export async function world(spec = {}) {
  const ctx = new Context({})
  const ran = []
  const logged = []
  ctx.logger.exporter({ levels: { default: 2 }, export: message => { logged.push(message) } })

  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)

  for (const toolName of spec.tools ?? ['bash', 'pwsh']) {
    ctx.tools.register(defineTool({
      name: toolName,
      description: `run a ${toolName} command`,
      parameters: {
        command: { type: 'string', required: true, description: 'the command' },
        description: { type: 'string', description: 'what it does' },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args) {
        ran.push({ tool: toolName, command: args.command })
        return 'ok'
      },
    }))
  }

  if (spec.plugin !== false) await ctx.plugin(plugin, spec.config ?? {})
  return { ctx, ran, logged }
}

/**
 * Run one command through the real registry.
 * @param harness - a harness from {@link world}.
 * @param command - the command line.
 * @param toolName - the tool to call.
 * @returns the normalized tool result.
 */
export function run(harness, command, toolName = 'bash') {
  return harness.ctx.tools.execute({
    signal: SIGNAL,
    callId: ToolCallId(`call-${Math.random().toString(36).slice(2)}`),
    name: toolName,
    arguments: { command, description: 'test' },
  })
}

/** The text of a result's first content block. */
export function resultText(result) {
  const block = result.content?.[0]
  return block?.type === 'text' ? block.text : ''
}

/** The captured log as one string. */
export function logText(logged) {
  return logged.map(message => message.args.map(argument => String(argument)).join(' ')).join('\n')
}
