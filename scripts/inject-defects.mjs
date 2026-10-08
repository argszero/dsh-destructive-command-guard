/**
 * Defect injection: mutate the source, rebuild, run the suite, and require that
 * the mutation is caught. An arm whose mutation leaves the suite green is
 * SILENT — it proves nothing about the suite, and it is reported as a failure of
 * the harness rather than hidden.
 *
 * The suite imports `lib/*.js`, not `src/*.ts`, so every arm **emits** first; a
 * mutation that is never written to `lib/` is a mutation the suite cannot see. A
 * mutation that does not compile is reported separately as TYPEFAIL, because it
 * never reached the suite either.
 *
 * Every arm below is a defect this plugin could plausibly have shipped: one
 * distinction it exists to make, removed one line at a time. The arms are not
 * "does the test file import the module" — each one deletes a rule the plugin
 * states in prose to its users, so a SILENT arm is a claim the package makes
 * that nothing checks.
 *
 * ```sh
 * node scripts/inject-defects.mjs                  # every arm
 * node scripts/inject-defects.mjs --filter=policy  # arms whose name matches
 * ```
 *
 * @module scripts/inject-defects
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const TSC = resolve(ROOT, 'node_modules/typescript/bin/tsc')

/** Each arm names the one distinction it removes, and the file it lives in. */
const MUTATIONS = [
  {
    // The whole reason the plugin exists. Without it the incident's command is
    // allowed, and the denial text that names the collision never appears.
    name: 'policy: the collision rule never fires',
    file: 'src/policy.ts',
    edits: [['const collided = [...powershell].filter(name => options.reserved.has(name))', 'const collided: string[] = []']],
  },
  {
    // The denial quotes the verb back, because the model recognises the line it
    // wrote by its verb; a denial about "rm" for a `Remove-Item` line is a
    // denial about a command the model does not think it ran.
    name: 'policy: the deletion verb is not carried into the denial',
    file: 'src/policy.ts',
    edits: [["            rule: 'reserved-collision',\n            verb: deletion.verb,",
      "            rule: 'reserved-collision',\n            verb: 'rm',"]],
  },
  {
    // `-WhatIf` removes nothing. Refusing it refuses the safe way to rehearse a
    // command, which is how a guard teaches an operator to unmount it.
    name: 'policy: a dry run is refused anyway',
    file: 'src/policy.ts',
    edits: [['      if (deletion.dry || (!deletion.recursive && !deletion.force)) continue', '      if (!deletion.recursive && !deletion.force) continue']],
  },
  {
    // A bare `rm $HOME` is an ordinary operand that happens to fail; only the
    // recursive or forced shape takes a tree with it.
    name: 'policy: a deletion that is neither recursive nor forced is refused',
    file: 'src/policy.ts',
    edits: [['      if (deletion.dry || (!deletion.recursive && !deletion.force)) continue', '      if (deletion.dry) continue']],
  },
  {
    name: 'policy: `~` is not read as a home reference',
    file: 'src/policy.ts',
    edits: [['const HOME_REFERENCE = /^(?:~|\\$(?:\\{)?(?:env:)?(?:home|userprofile)(?:\\})?|%userprofile%)$/i',
      'const HOME_REFERENCE = /^(?:\\$(?:\\{)?(?:env:)?(?:home|userprofile)(?:\\})?|%userprofile%)$/i']],
  },
  {
    name: 'policy: the contents of the home directory are not read as the home directory',
    file: 'src/policy.ts',
    edits: [["  if (HOME_CONTENTS.test(text)) return 'home-contents'", "  if (false) return 'home-contents'"]],
  },
  {
    // The distinction that keeps a POSIX cleanup from being a false accusation:
    // `home=/srv/scratch; rm -rf $home` assigns with a spelling that works, so
    // the operand is the author's value rather than the runtime's.
    name: 'policy: a name the command shadowed still reads as the home directory',
    file: 'src/policy.ts',
    edits: [['if (name !== undefined && options.shadowed.has(name)) return undefined', 'if (false) return undefined']],
  },
  {
    name: 'policy: a literal path equal to the home directory is not refused',
    file: 'src/policy.ts',
    edits: [["  if (normalized === normalizePath(options.home)) return 'home'", "  if (false) return 'home'"]],
  },
  {
    name: 'policy: an operator-protected path is not protected',
    file: 'src/policy.ts',
    edits: [["    if (normalized === normalizePath(candidate)) return 'protected'", "    if (false) return 'protected'"]],
  },
  {
    name: 'policy: a drive root is not read as a root',
    file: 'src/policy.ts',
    edits: [['if (FILESYSTEM_ROOT.test(text) || DRIVE_ROOT.test(text) || SYSTEM_DRIVE.test(text)) return \'root\'',
      'if (FILESYSTEM_ROOT.test(text) || SYSTEM_DRIVE.test(text)) return \'root\'']],
  },
  {
    // The reported incident's own spelling: `$home = "…"`, with the `=` on its
    // own word. Losing it loses the assignment, and with it the collision.
    name: 'scan: the spaced `$name = …` assignment is not read',
    file: 'src/scan.ts',
    edits: [['if (POWERSHELL_BARE.test(token.text) && tokens[index + 1]?.text === \'=\') {', 'if (false) {']],
  },
  {
    // `rm -rf "$BUILD_DIR"` — the value is quoted, the deletion is real.
    name: 'scan: a quoted operand is not read as a target',
    file: 'src/scan.ts',
    edits: [['    if (token.quoted) {\n      targets.push(word)\n      continue\n    }', '    if (token.quoted) continue']],
  },
  {
    name: 'scan: a bundled short flag is not read as a flag',
    file: 'src/scan.ts',
    edits: [['if (bundle.length <= 4 && BUNDLE_LETTERS.test(bundle)) {', 'if (false) {']],
  },
  {
    name: 'scan: a cmd-style flag is not read as a flag',
    file: 'src/scan.ts',
    edits: [['if (cmdStyle && CMD_FLAG.test(word)) {', 'if (false) {']],
  },
  {
    // `rmdir`/`rd` write `/s /q`; the PowerShell spellings write `-Recurse
    // -Force`. One dialect losing its flags is a whole family of misses.
    name: 'scan: `-Force` alone is not read as force',
    file: 'src/scan.ts',
    edits: [["if (parameter === '-force') {", 'if (false) {']],
  },
  {
    // `echo rm -rf ~` must not read as a deletion. Widening the verb search is
    // how that false accusation gets shipped.
    name: 'scan: any word before a verb is accepted',
    file: 'src/scan.ts',
    edits: [['    if (!isPrefix) return undefined', '    if (false) return undefined']],
  },
  {
    // `set home=…` assigns with a spelling that works, in the dialect that
    // spells it that way.
    name: 'scan: `set name=…` does not read the assignment',
    file: 'src/scan.ts',
    edits: [["const set = PLAIN_ASSIGNMENT.exec(tokens[index + 1]?.text ?? '')", "const set = PLAIN_ASSIGNMENT.exec('')"]],
  },
  {
    name: 'index: an exempt command is refused anyway',
    file: 'src/index.ts',
    edits: [['  if (isExempt(command, settings)) return undefined', '  if (false) return undefined']],
  },
  {
    name: 'index: `onlyTools` is ignored',
    file: 'src/index.ts',
    edits: [['  if (settings.onlyTools.length > 0 && !settings.onlyTools.includes(exec.name)) return undefined', '  if (false) return undefined']],
  },
  {
    name: 'index: an empty `onlyTools` inspects nothing',
    file: 'src/index.ts',
    edits: [['  if (settings.onlyTools.length > 0 && !settings.onlyTools.includes(exec.name)) return undefined',
      '  if (!settings.onlyTools.includes(exec.name)) return undefined']],
  },
  {
    // `report` exists so the guard can be measured before it is trusted; a
    // report that refuses has taken away the only way to measure it.
    name: 'index: report mode refuses anyway',
    file: 'src/index.ts',
    edits: [["        ctx.logger.warn(`destructive-command-guard (report): would refuse ${exec.name}: ${reason}`)\n        return next()\n",
      "        ctx.logger.warn(`destructive-command-guard (report): would refuse ${exec.name}: ${reason}`)\n"]],
  },
  {
    name: 'index: `off` mode installs the guard anyway',
    file: 'src/index.ts',
    edits: [["  if (settings.mode === 'off') return\n", '']],
  },
  {
    name: 'index: the inspection tool is registered even when it is turned off',
    file: 'src/index.ts',
    edits: [['  const tool = settings.tool ? ctx.tools.register(checkTool(settings)) : undefined',
      '  const tool = ctx.tools.register(checkTool(settings))']],
  },
  {
    // The whole point of a reason is that the model can see what it is being
    // told about; a denial that does not echo the command is a denial about
    // nothing in particular.
    name: 'index: the denial does not echo the command it read',
    file: 'src/index.ts',
    edits: [['  return renderDenial(findings, command, settings.maxReasonChars)', "  return renderDenial(findings, '', settings.maxReasonChars)"]],
  },
  {
    name: 'index: an empty command is inspected',
    file: 'src/index.ts',
    edits: [["      if (command.trim() === '') return 'destructive_command_check: the command argument is empty; nothing to check.'", '      if (false) return \'\'']],
  },
  {
    // A model that cannot tell whether the command ran will often assume it did.
    name: 'advice: the closing sentence is dropped',
    file: 'src/advice.ts',
    edits: [["  const trailer = 'Nothing was executed.'", "  const trailer = ''"]],
  },
  {
    // The bound is spent on the quote; spending it on the whole text is how the
    // sentence that names the fix becomes the one that gets cut off — which is
    // the defect this budget was rewritten to fix.
    name: 'advice: the whole text is truncated instead of the quote',
    file: 'src/advice.ts',
    edits: [['  const bodyRoom = maxChars - head.length - trailer.length - 4', '  const bodyRoom = Number.MAX_SAFE_INTEGER']],
  },
  {
    // The denial must say which read-only name was assigned, in the spelling
    // that makes the collision legible (`$home` is the automatic `$HOME`).
    name: 'advice: the automatic variable is named in its colliding spelling',
    file: 'src/advice.ts',
    edits: [['` is the automatic variable \\`$${name.toUpperCase()}\\`,', '` is the automatic variable \\`$${name}\\`,']],
  },
  {
    // A collision is fixed by renaming a variable; a home-target is fixed by
    // naming a path. Saying the wrong one costs the model another turn.
    name: 'advice: a collision is remedied by naming a path',
    file: 'src/advice.ts',
    edits: [["  return finding.rule === 'reserved-collision'", "  return finding.rule === 'home-target'"]],
  },
  {
    // Two operands tripping one rule is one reason, not the same reason twice.
    name: 'advice: the findings are not deduplicated by rule',
    file: 'src/advice.ts',
    edits: [['    if (seen.has(finding.rule)) continue', '    if (false) continue']],
  },
  {
    name: 'config: a mode that is not `off` is enforcing',
    file: 'src/config.ts',
    edits: [["    mode: config.mode === 'off' || config.mode === 'report' ? config.mode : 'enforce',", "    mode: config.mode === 'off' ? 'off' : 'enforce',"]],
  },
  {
    // A bound that is not a usable number must fall back, not reach the
    // renderer as written: `slice(0, -5)` is a mangled reason, not a short one.
    name: 'config: a bound that is not a positive integer is kept',
    file: 'src/config.ts',
    edits: [["  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : fallback", '  return value ?? fallback']],
  },
  {
    name: 'config: the extra automatic names are ignored',
    file: 'src/config.ts',
    edits: [["  for (const name of strings(config.extraReserved, [])) reserved.add(name.toLowerCase())\n", '']],
  },
  {
    name: 'config: the protected paths are ignored',
    file: 'src/config.ts',
    edits: [["    protectedPaths: [...new Set([...protectedPaths, dirname(home)].filter(path => path !== home && path !== '/' && path !== ''))],", '    protectedPaths: [],']],
  },
  {
    // The home directory is derived, not guessed: an operator who sets nothing
    // gets the account the plugin actually runs as.
    name: 'config: the home directory is not derived from the account',
    file: 'src/config.ts',
    edits: [['    : homedir()', "    : ''"]],
  },
]

const argv = process.argv.slice(2)
const filter = argv.find(argument => argument.startsWith('--filter='))?.slice('--filter='.length)

/**
 * Run one command, capturing whether it succeeded.
 *
 * The timeout is not decoration: an arm that removes a guard from a path the
 * plugin observes can leave a rejected promise unhandled, and a mutant that
 * never terminates is a mutant the suite cannot report on. It is killed here
 * and counted as caught, which is what it is — the suite never reaches its
 * assertions because the code under test never returns.
 */
function run(command, args) {
  try {
    execFileSync(command, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], timeout: 300_000 })
    return { ok: true, output: '' }
  } catch (error) {
    return { ok: false, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

/** Emit the compiled artifact the suite actually imports. */
function build() {
  return run(process.execPath, [TSC])
}

/** Run every spec in the suite. */
function test() {
  return run(process.execPath, ['--test', 'test/*.spec.mjs'])
}

const results = []
for (const mutation of MUTATIONS) {
  if (filter !== undefined && !mutation.name.includes(filter)) continue
  const path = resolve(ROOT, mutation.file)
  const original = readFileSync(path, 'utf8')
  let mutated = original
  let applied = true
  for (const [from, to] of mutation.edits) {
    if (!mutated.includes(from)) {
      applied = false
      break
    }
    mutated = mutated.replace(from, to)
  }
  if (!applied) {
    results.push({ name: mutation.name, outcome: 'NO-OP', detail: 'the source no longer contains the text this arm mutates' })
    continue
  }
  try {
    writeFileSync(path, mutated)
    const built = build()
    if (!built.ok) {
      results.push({ name: mutation.name, outcome: 'TYPEFAIL', detail: 'the mutation does not compile, so the suite never ran' })
      continue
    }
    const tested = test()
    results.push(tested.ok
      ? { name: mutation.name, outcome: 'SILENT', detail: 'the suite stayed green — this arm proves nothing' }
      : { name: mutation.name, outcome: 'CAUGHT', detail: '' })
  } finally {
    writeFileSync(path, original)
  }
}

// Put `lib/` back. The last arm left its mutation COMPILED there — the source is
// restored in the `finally` above, but the build output is not, and a checkout
// that runs this script and then publishes would ship the last mutant. Rebuilt
// once here so the tree is consistent whether a human runs this or CI does.
const restored = build()
if (!restored.ok) {
  process.stdout.write('\nWARNING: the rebuild after restoring the sources failed — lib/ may hold a mutant\n')
}

const caught = results.filter(result => result.outcome === 'CAUGHT').length
const declared = new Set(MUTATIONS.filter(mutation => mutation.equivalent !== undefined).map(mutation => mutation.name))
const equivalents = results.filter(result => result.outcome === 'SILENT' && declared.has(result.name))
const silent = results.filter(result => result.outcome === 'SILENT' && !declared.has(result.name))
const other = results.filter(result => result.outcome !== 'CAUGHT' && result.outcome !== 'SILENT')

for (const result of results) {
  const label = result.outcome === 'SILENT' && declared.has(result.name) ? 'EQUIVALENT' : result.outcome
  process.stdout.write(`${label.padEnd(10)} ${result.name}${result.detail === '' ? '' : `\n           ${result.detail}`}\n`)
}
process.stdout.write(`\n${caught}/${results.length} caught`)
process.stdout.write(silent.length === 0
  ? ` — no arm is silent (${equivalents.length} declared equivalent — see the arms)\n`
  : `, ${silent.length} SILENT\n`)
if (other.length > 0) {
  process.stdout.write(`${other.length} arm(s) could not be evaluated: ${other.map(result => `${result.outcome} ${result.name}`).join(', ')}\n`)
}
process.exitCode = silent.length === 0 && other.length === 0 ? 0 : 1
