/**
 * The end-to-end witness: the refusal happens through the real registry, the
 * tool body does not run, and the same command runs when the plugin is absent.
 *
 * The control arm is not decoration. Without it, "the result was an error" is
 * consistent with the tool being broken, the arguments being rejected, or the
 * command being refused by something else entirely — none of which would be this
 * plugin working. With it, the difference between the two runs is the plugin and
 * nothing else.
 *
 * @module test/guard.spec
 */

import { strict as assert } from 'node:assert'
import { homedir } from 'node:os'
import { describe, it } from 'node:test'
import { logText, resultText, run, world } from './harness.mjs'

/** The reported incident, verbatim in shape: the reported command, on Windows paths. */
const INCIDENT = [
  'chcp 65001 > $null',
  '$home = "C:\\work\\out\\vacuum-repro\\fakehome"',
  'Remove-Item $home -Recurse -Force -ErrorAction SilentlyContinue',
  'node "C:\\work\\out\\vacuum-repro\\e2e.mjs" $home 2>&1 | Out-String -Width 200',
].join('\n')

describe('an automatic-variable collision', () => {
  it('is refused, and the command never reaches the tool body', async () => {
    const harness = await world()
    const result = await run(harness, INCIDENT)

    assert.equal(result.isError, true, 'the call must be refused')
    assert.deepEqual(harness.ran, [], 'a refused call must never reach the tool body')
    const text = resultText(result)
    assert.match(text, /Error: destructive-command-guard refused this command before it ran\./)
    assert.match(text, /automatic-variable collision/)
    assert.match(text, /deletes the value the runtime gave that name/)
  })

  it('succeeds when the plugin is not mounted (the control arm)', async () => {
    const harness = await world({ plugin: false })
    const result = await run(harness, INCIDENT)

    assert.notEqual(result.isError, true, 'without the plugin the same call must run')
    assert.equal(harness.ran.length, 1, 'the control arm must reach the tool body')
    assert.equal(harness.ran[0].command, INCIDENT)
  })

  it('a collision alone is remedied by renaming a variable, not by naming a path', async () => {
    const harness = await world()
    const text = resultText(await run(harness, '$pwd = "C:\\out"\nRemove-Item $pwd -Recurse -Force'))

    assert.match(text, /automatic-variable collision \(`pwd`\)/)
    assert.match(text, /Rename the variable/)
    assert.match(text, /remove-item -Recurse -Force \$pwd/i,
      'the denial quotes the verb back, so the model recognises the line it wrote')
    assert.doesNotMatch(text, /Name the path you mean explicitly/,
      'a collision is fixed by renaming the variable; naming a path is the other rule\'s remedy')
  })

  it('names the variable, the verb and the remedy the model needs', async () => {
    const harness = await world()
    const text = resultText(await run(harness, INCIDENT))

    assert.match(text, /`\$home = …` does not create a variable/)
    assert.match(text, /case-insensitive/)
    assert.match(text, /`\$Home`|`\$HOME`/)
    assert.match(text, /remove-item -Recurse -Force \$home/i)
    assert.match(text, /Rename the variable/)
    assert.match(text, /Nothing was executed\./)
    assert.match(text, /\$home = "C:\\work\\out\\vacuum-repro\\fakehome"/,
      'the denial must echo the command it read, so the model knows what it is being told about')
  })
})

describe('a protected location', () => {
  for (const [label, command] of [
    ['$HOME on PowerShell', 'Remove-Item $HOME -Recurse -Force'],
    ['~ on POSIX', 'rm -rf ~'],
    ['$env:USERPROFILE', 'Remove-Item "$env:USERPROFILE" -Recurse -Force'],
    ['a filesystem root', 'rm -rf /'],
    ['a drive root from cmd', 'rd /s /q C:\\'],
    ['the contents of the home directory', 'rm -rf $HOME/*'],
    ['a forced, non-recursive deletion', 'Remove-Item $HOME -Force'],
    ['the home directory by its literal path', `rm -rf ${homedir()}`],
  ]) {
    it(`is refused: ${label}`, async () => {
      const harness = await world()
      const result = await run(harness, command)

      assert.equal(result.isError, true, `${label} must be refused`)
      assert.deepEqual(harness.ran, [], `${label}: the body must not run`)
      assert.match(resultText(result), /deletion of a protected location/)
    })
  }

  it('succeeds when the plugin is not mounted (the control arm)', async () => {
    const harness = await world({ plugin: false })
    const result = await run(harness, 'rm -rf ~')

    assert.notEqual(result.isError, true)
    assert.equal(harness.ran.length, 1)
  })
})

describe('the denial is one text, not a list of operands', () => {
  it('states each rule once, however many operands trip it', async () => {
    const harness = await world()
    const text = resultText(await run(harness, 'rm -rf ~ $HOME'))

    assert.equal(text.match(/• deletion of a protected location/g)?.length, 1,
      'two operands tripping one rule is one reason, not two')
  })

  it('a nonsensical bound falls back instead of mangling the reason', async () => {
    const harness = await world({ config: { maxReasonChars: -5 } })

    assert.match(resultText(await run(harness, INCIDENT)), /Nothing was executed\./)
  })
})

describe('the denial stays inside its budget', () => {
  it('a command long enough to blow the budget still keeps the sentence that says nothing ran', async () => {
    const harness = await world()
    const text = resultText(await run(harness, `rm -rf ~ ${'x'.repeat(4000)}`))

    assert.match(text, /deletion of a protected location/)
    assert.match(text, /Nothing was executed\./)
  })

  it('a budget too small for the reasons keeps the sentence rather than the tail', async () => {
    const harness = await world({ config: { maxReasonChars: 300 } })
    const text = resultText(await run(harness, INCIDENT))

    assert.ok(text.length <= 'Error: '.length + 300, `the reason must respect the bound, saw ${text.length}`)
    assert.match(text, /Nothing was executed\./)
  })
})

describe('mode', () => {
  it("report logs the finding and lets the call run", async () => {
    const harness = await world({ config: { mode: 'report' } })
    const result = await run(harness, 'rm -rf ~')

    assert.notEqual(result.isError, true, 'report mode must not refuse')
    assert.equal(harness.ran.length, 1, 'report mode must still dispatch')
    assert.match(logText(harness.logged), /destructive-command-guard \(report\): would refuse bash/)
  })

  it('off installs nothing: the same call runs and nothing is logged', async () => {
    const harness = await world({ config: { mode: 'off' } })
    const result = await run(harness, 'rm -rf ~')

    assert.notEqual(result.isError, true)
    assert.equal(harness.ran.length, 1)
    assert.equal(logText(harness.logged), '', 'off must not log anything at all')
  })
})

describe('the knobs that keep the guard usable', () => {
  it('exempt wins over a matching rule', async () => {
    const harness = await world({ config: { exempt: ['rm -rf ~'] } })
    const result = await run(harness, 'rm -rf ~')

    assert.notEqual(result.isError, true, 'an exempt command must run')
    assert.equal(harness.ran.length, 1)
  })

  it('onlyTools keeps a call from another tool out of the guard', async () => {
    const harness = await world({ tools: ['bash', 'custom-shell'], config: { onlyTools: ['bash'] } })
    // The command is over the line, but this tool is not one the guard inspects.
    const result = await run(harness, 'rm -rf ~', 'custom-shell')

    assert.notEqual(result.isError, true)
    assert.equal(harness.ran.length, 1)
  })

  it('an empty onlyTools inspects any tool carrying a command string', async () => {
    const harness = await world({ tools: ['custom-shell'], config: { onlyTools: [] } })
    const result = await run(harness, 'rm -rf ~', 'custom-shell')

    assert.equal(result.isError, true)
    assert.deepEqual(harness.ran, [])
  })

  it('an operator can widen the automatic set and the protected paths', async () => {
    const extra = await world({ config: { extraReserved: ['scratch'] } })
    const collision = await run(extra, '$scratch = "C:\\out"\nRemove-Item $scratch -Recurse -Force')
    assert.equal(collision.isError, true, 'a name the operator listed is an automatic name here')
    assert.match(resultText(collision), /automatic-variable collision \(`scratch`\)/)

    const paths = await world({ config: { protectedPaths: ['/opt/data'] } })
    const protectedPath = await run(paths, 'rm -rf /opt/data')
    assert.equal(protectedPath.isError, true, 'a path the operator listed must not be deleted')
    assert.match(resultText(protectedPath), /deletion of a protected location \(protected\)/)
  })

  it('a rule can be turned off on its own', async () => {
    const collisionsOff = await world({ config: { reservedCollision: false } })
    const stillDenied = await run(collisionsOff, 'Remove-Item $HOME -Recurse -Force')
    assert.equal(stillDenied.isError, true,
      'with the collision rule off, the home rule still refuses this one — that is the point of the pair')
    assert.deepEqual(collisionsOff.ran, [])

    const homeOff = await world({ config: { homeTarget: false } })
    // Only the home rule can see this one: `~` is not a name, so no assignment is involved.
    const result = await run(homeOff, 'rm -rf ~')
    assert.notEqual(result.isError, true, 'with the home rule off, a bare home reference is allowed')
  })
})

describe('the inspection tool', () => {
  it('answers the same decision the guard would make, without running anything', async () => {
    const harness = await world()
    const refused = await harness.ctx.tools.execute({
      signal: new AbortController().signal,
      callId: 'check-1',
      name: 'destructive_command_check',
      arguments: { command: 'Remove-Item $home -Recurse -Force' },
    })

    assert.notEqual(refused.isError, true, 'a check is not itself refused')
    assert.match(resultText(refused), /^REFUSED \(enforce mode\):/)
    assert.deepEqual(harness.ran, [], 'checking a command must not run it')
  })

  it('reports an allowed command as allowed', async () => {
    const harness = await world()
    const allowed = await harness.ctx.tools.execute({
      signal: new AbortController().signal,
      callId: 'check-2',
      name: 'destructive_command_check',
      arguments: { command: 'rm -rf /tmp/build' },
    })

    assert.match(resultText(allowed), /^ALLOWED: no rule matches this command\./)
  })

  it('says so when there is nothing to check', async () => {
    const harness = await world()
    const empty = await harness.ctx.tools.execute({
      signal: new AbortController().signal,
      callId: 'check-empty',
      name: 'destructive_command_check',
      arguments: { command: '   ' },
    })

    assert.match(resultText(empty), /the command argument is empty; nothing to check/)
    assert.deepEqual(harness.ran, [])
  })

  it('is not registered when the tool is turned off', async () => {
    const harness = await world({ config: { tool: false } })
    assert.equal(harness.ctx.tools.get('destructive_command_check'), undefined)
  })
})

describe('the guard does not get in the way', () => {
  for (const command of [
    'rm -rf /tmp/build',
    'rm -rf "$BUILD_DIR" -f',
    'Remove-Item -Path ./out -Recurse -Force',
    'find . -name "*.log" -delete',
    'Remove-Item $HOME -Recurse -Force -WhatIf',
    'echo "rm -rf ~"',
    'home=/srv/scratch; rm -rf $home',
    'rm -rf ~/scratch',
    'rm /tmp/out',
    'rm $HOME',
    'echo rm -rf ~',
    'set "home=/srv/scratch"\nrm -rf $home',
  ]) {
    it(`allows: ${command}`, async () => {
      const harness = await world()
      const result = await run(harness, command)

      assert.notEqual(result.isError, true, `this must not be refused: ${command}`)
      assert.equal(harness.ran.length, 1)
    })
  }
})
