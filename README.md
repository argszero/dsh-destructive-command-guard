# @argszero/dsh-destructive-command-guard

Refuses a shell command before it runs when the command deletes something it did
not name.

Two things, both of them facts about the text rather than guesses about intent:

- an **automatic-variable collision** — a read-only automatic name is assigned,
  and then used as the operand of a recursive or forced deletion, so the operand
  holds the value the runtime gave that name rather than the one the line
  appears to name;
- a **protected location** — a recursive or forced deletion whose operand is a
  home reference (`$HOME`, `$home`, `~`, `$env:USERPROFILE`) or a filesystem
  root.

A `deny` at `tools/pre-execute` short-circuits the pipeline: the tool body never
runs, and the operator is never asked to approve a command that is then refused.

## The problem

The reported incident ([#9173](https://github.com/deepseek-ai/deepseek-harness/discussions/9173))
is the clean example. An agent preparing a test fixture wrote:

```powershell
$home = "C:\work\out\vacuum-repro\fakehome"
Remove-Item $home -Recurse -Force
```

In PowerShell variable names are **case-insensitive** and the automatic
variables are **read-only**, so `$home` *is* `$HOME`. The assignment fails as a
non-terminating error, `$ErrorActionPreference` defaults to `Continue`, the very
next statement runs anyway — and it removes the operator's real profile: SSH
keys, credential stores, and the configuration the session itself lives in.
`-ErrorAction SilentlyContinue` on the deletion makes it quieter still.

The command contains no `C:\Users\…`, no `~` and no `$env:USERPROFILE`. Every
path in it is a workspace path. What makes it dangerous is a fact about the
*language*, which is why neither a path pattern nor a careful reading of the
text catches it — and why a rule anchored to that fact does.

## Install

```sh
npm install @argszero/dsh-destructive-command-guard@0.1.1
```

Then mount it. The package ships a bundle patch
(`dsh.bundle.patch: ./cordis.patch.yml`), so a deployment that follows the
harness's bundle convention gets it by adding one entry:

```yaml
- insert:
    - id: destructive-command-guard
      name: '@argszero/dsh-destructive-command-guard'
```

Mounting it directly works the same way and takes the same config:

```ts
import guard from '@argszero/dsh-destructive-command-guard'

ctx.plugin(guard, { mode: 'report' })   // measure before you enforce
```

## What it refuses

| command | verdict |
|---|---|
| `$home = "…"; Remove-Item $home -Recurse -Force` | **refused** — automatic-variable collision |
| `Remove-Item $HOME -Recurse -Force` | **refused** — home reference |
| `rm -rf ~` | **refused** — home reference |
| `rm -rf /` | **refused** — filesystem root |
| `rm -rf $HOME/*` | **refused** — the contents of the home directory |
| `rd /s /q C:\` | **refused** — drive root |
| `rm -rf "$BUILD_DIR"` | allowed — an ordinary variable is not a collision |
| `rm -rf ~/scratch` | allowed — a subdirectory is not the home directory |
| `rm -rf /tmp/build` | allowed |
| `Remove-Item $HOME -Recurse -Force -WhatIf` | allowed — `-WhatIf` does not delete |
| `echo "rm -rf ~"` | allowed — the text is not the command |

When it refuses, the reason it returns is written to be *acted on*, because a
refusal the model cannot act on costs a turn:

```
Error: destructive-command-guard refused this command before it ran.

Command read as:
$home = "C:\work\out\vacuum-repro\fakehome"
Remove-Item $home -Recurse -Force -ErrorAction SilentlyContinue

• automatic-variable collision (`home`)
`$home = …` does not create a variable. In PowerShell variable names are
case-insensitive, so `$home` is the automatic variable `$HOME`, which is
read-only: … so `remove-item -Recurse -Force $home` deletes the value the
runtime gave that name, not the one this line appears to name.
Rename the variable (any name that is not a PowerShell automatic variable) and retry.

Nothing was executed.
```

The reasons and the closing sentence are paid for first, out of the budget
`maxReasonChars` sets; only the echo of the command is trimmed, and only when
what is left over is too little to be worth a line. A model that cannot tell
whether the command ran will often assume it did.

## Configuration

| option | default | meaning |
|---|---|---|
| `mode` | `'enforce'` | `enforce` refuses; `report` logs the same finding and lets the call run; `off` installs nothing |
| `reservedCollision` | `true` | apply the automatic-variable collision rule |
| `homeTarget` | `true` | apply the protected-location rule |
| `extraReserved` | `[]` | extra automatic variable names, alongside the built-in set |
| `protectedPaths` | `[]` | extra absolute paths a deletion must not target |
| `homeDirectory` | `os.homedir()` | the home directory to protect |
| `exempt` | `[]` | commands containing any of these substrings are never refused |
| `onlyTools` | `['bash', 'pwsh']` | the tools to inspect; an empty list inspects every tool with a `command` string |
| `tool` | `true` | register the `destructive_command_check` tool |
| `maxReasonChars` | `1200` | inclusive bound on the denial reason delivered to the model |

`mode: 'report'` is how the guard is observed before it is trusted — a guard that
cannot be measured gets unmounted after its first surprise. `off` answers "is
this plugin responsible for the behaviour I am seeing" without uninstalling it.

The `destructive_command_check` tool answers the same question on demand, without
running anything:

```
> destructive_command_check("Remove-Item $home -Recurse -Force")
REFUSED (enforce mode):

destructive-command-guard refused this command before it ran.
…
```

## Honest boundaries

- **It is a lexical scan, not a parser.** It splits the command into statements,
  reads the assignments and the deletion invocations, and decides on those. A
  command that builds a name indirectly (`& $cmd`), or that assigns through
  `Set-Variable`, or that deletes through a wrapper script, is not read. The
  rules are stated in `src/policy.ts` and the reading in `src/scan.ts`; both say
  what they cannot see.
- **It is not a sandbox.** It refuses a shape; it does not confine a process.
  A command that deletes the same directory by a deliberate path is allowed, and
  should be — that is what `exempt` and `protectedPaths` are for.
- **It fails open.** An unexpected error in its own scan is logged and the call
  proceeds. A plugin whose bug could refuse every tool call in a deployment is a
  worse failure than the one it prevents.
- **It was not reproduced locally.** The incident is a Windows behaviour: there
  is no PowerShell on the machine this plugin was developed on, so the rules were
  verified against the reported command text and against the PowerShell language
  rules, not by running `$home` and watching it delete a profile.

## Compatibility

This plugin reads the tool registry's `tools/pre-execute` waterfall and its
`PreToolDecision` type, so its peer range names the lines it was verified
against — every one of them pinned and run, not inferred:

- `@deepseek-ai/dsh-tools`: `>=0.1.7-rc.2 <0.2.0 || >=0.2.0-rc.2 <0.2.0`
- `@deepseek-ai/cordis`: `^4.0.2`

Verified against the `0.1.7-rc.2` and `0.2.0-rc.2` lines (`npm run
test:probe-lines` pins every harness package to one line, asserts the pins took,
and runs the suite against it). Each `||` segment's floor is the build that was
actually run, so the range and the probed set are the same set — a line this
plugin has not been run on is a line it does not claim.

## License

MIT
