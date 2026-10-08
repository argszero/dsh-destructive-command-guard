/**
 * The denial text.
 *
 * A refusal the model cannot act on is a refusal that costs a turn: the model
 * sees `Error: <reason>`, has no other signal about what was wrong, and will
 * usually retry the same command slightly reworded. So each rule is worded to
 * say three things in order — what was read, why that reading is certain, and
 * what to write instead — and the two rules are worded differently because their
 * fixes are different. A collision is fixed by *renaming a variable*; a
 * home-target is fixed by naming a path. Saying the wrong one costs another turn.
 *
 * @module @argszero/dsh-destructive-command-guard/advice
 */

import type { Finding } from './policy.ts'

/** The verb as a caller recognises it, with the dialect's flag spelling kept. */
function invocation(finding: Finding): string {
  const flags: string[] = []
  if (finding.recursive) flags.push(finding.verb === 'rm' ? '-r' : '-Recurse')
  if (finding.force) flags.push(finding.verb === 'rm' ? '-f' : '-Force')
  return [finding.verb, ...flags, finding.target].join(' ')
}

/** Why a reserved name cannot be assigned, and what that means for the operand. */
function collision(finding: Finding): string {
  const name = finding.name as string
  return [
    `\`$${name} = …\` does not create a variable. In PowerShell variable names are`
    + ` case-insensitive, so \`$${name}\` is the automatic variable \`$${name.toUpperCase()}\`,`
    + ' which is read-only: the assignment fails as a non-terminating error, and with'
    + " `$ErrorActionPreference` at its default `Continue` the statement after it runs"
    + ` anyway — so \`${invocation(finding)}\` deletes the value the runtime gave that name,`
    + ' not the one this line appears to name.',
  ].join('\n')
}

/** Why an operand is the home directory, said in the operand's own terms. */
function location(finding: Finding): string {
  const target = finding.target
  switch (finding.shape) {
    case 'home-contents':
      return `\`${target}\` is everything directly inside the home directory, so `
        + `\`${invocation(finding)}\` removes the operator's profile contents without naming them.`
    case 'root':
      return `\`${target}\` is a filesystem root, so \`${invocation(finding)}\` removes the whole volume.`
    case 'protected':
      return `\`${target}\` is one of the paths this deployment marked as protected.`
    default:
      return `\`${target}\` resolves to the home directory of the account running the command,`
        + ` so \`${invocation(finding)}\` removes the profile itself — SSH keys, credential`
        + ' stores and configuration live there, and the removal is not reversible from'
        + ' inside the session.'
  }
}

/** The one thing to do instead, per rule. */
function remedy(finding: Finding): string {
  return finding.rule === 'reserved-collision'
    ? `Rename the variable (any name that is not a PowerShell automatic variable) and retry.`
    : 'Name the path you mean explicitly, under the workspace, and retry — or, if this'
      + ' deletion is deliberate, add the command to the plugin’s `exempt` list.'
}

/**
 * Render the denial for one command.
 *
 * The findings are deduplicated by rule so a command that trips both rules is one
 * denial with two reasons rather than the same reason twice, and the result is
 * bounded: a reason is delivered to the model inside an error result, so a text
 * that can grow without a bound is a text that can displace the conversation it
 * is meant to correct.
 *
 * The bound is spent in priority order, and the order is the whole point. The
 * reasons and the remedy are what the model must read to correct itself; the
 * closing "Nothing was executed." is what tells it the command did not run, and a
 * model that cannot tell will often assume it did. The echo of the command is the
 * only part the caller controls the length of, and a command long enough to blow
 * the budget is exactly one whose tail the reasons already describe. So the quote
 * is paid for last, out of whatever is left, and dropped when too little is left
 * to be worth a line — which keeps a plain tail truncation of the whole text from
 * cutting off the sentence that names the fix.
 * @param findings - every finding for the command.
 * @param command - the command line, quoted back so the model knows what was read.
 * @param maxChars - the inclusive bound for the whole reason.
 * @returns the denial reason.
 */
export function renderDenial(findings: readonly Finding[], command: string, maxChars: number): string {
  const head = 'destructive-command-guard refused this command before it ran.'
  const trailer = 'Nothing was executed.'
  const label = 'Command read as:\n'
  const seen = new Set<string>()
  const sections: string[] = []
  for (const finding of findings) {
    if (seen.has(finding.rule)) continue
    seen.add(finding.rule)
    sections.push([
      finding.rule === 'reserved-collision'
        ? `• automatic-variable collision (\`${finding.name}\`)`
        : `• deletion of a protected location (${finding.shape})`,
      finding.rule === 'reserved-collision' ? collision(finding) : location(finding),
      remedy(finding),
    ].join('\n'))
  }
  const body = sections.join('\n\n')
  // The reasons and the trailer are reserved their room before the quote is
  // considered at all; only an over-long body is trimmed, and only from the tail.
  const bodyRoom = maxChars - head.length - trailer.length - 4
  const bodyOut = body.length <= bodyRoom ? body : `${body.slice(0, Math.max(0, bodyRoom - 1))}…`
  const fixed = `${head}\n\n${bodyOut}\n\n${trailer}`
  const spare = maxChars - fixed.length - label.length - 2
  if (spare < 32) return fixed.length <= maxChars ? fixed : `${fixed.slice(0, maxChars - 1)}…`
  const quoted = command.length > spare ? `${command.slice(0, spare - 1)}…` : command
  return `${head}\n\n${label}${quoted}\n\n${bodyOut}\n\n${trailer}`
}
