/**
 * A lexical scan of a shell command line — deliberately small, and deliberately
 * not a parser.
 *
 * The guard has to answer one question about text it did not write: *does this
 * command delete something the author did not mean to name?* Answering it needs
 * only three things from the surface syntax — where one statement ends, what the
 * statement's verb is, and which of its words are flags rather than operands —
 * so this module produces exactly that and stops.
 *
 * **What it is for.** A deletion is dangerous here not because of the path it
 * contains but because of the path it *does not* contain: `Remove-Item $home
 * -Recurse -Force` names a variable, and in PowerShell that variable is the
 * user's home directory no matter what an earlier line tried to assign to it.
 * That is a property of the token, not of any value, so a scanner can decide it.
 *
 * **What it cannot do**, stated here rather than discovered later:
 * - It does not understand quoting semantics beyond tracking quote state, so a
 *   command built at run time (`Invoke-Expression $cmd`, `sh -c "$x"`,
 *   `pwsh -EncodedCommand …`) is text it reads as something else.
 * - It does not follow values. `X=$HOME; rm -rf $X` is two steps it will not
 *   connect; only the variable that *is* a home reference is recognised.
 * - It does not see piped input. `Get-ChildItem $HOME | Remove-Item -Recurse
 *   -Force` has no operand to read, because the operand arrives on the pipe.
 * - It splits a command on `;`, newlines, `|`, `&&` and `||` only, so a command
 *   substituted into an argument (`rm -rf $(…)`) is one operand it cannot
 *   decompose.
 *
 * Every one of those is a *miss*, never a false accusation: the scanner only
 * reports what it can read literally. The guard's contract — refuse what is
 * certainly wrong, stay quiet about everything else — is what makes a scanner,
 * rather than a parser, the right size.
 *
 * @module @argszero/dsh-destructive-command-guard/scan
 */

/** One word of a command, with the information the rules need about it. */
export interface Token {
  /**
   * The word's text with surrounding quotes removed. A word assembled from
   * quoted and unquoted pieces is concatenated, which is what a shell would do.
   */
  readonly text: string
  /**
   * True when the word *begins* with a quote, so the whole word is a literal.
   *
   * Beginning-with rather than contains is the boundary the rules need: a word
   * that starts unquoted but ends in a quoted run is a command built from both
   * — `$home="<path>"` is an assignment whose value happens to be quoted, and
   * reading it as data would lose the assignment — while a word that starts
   * quoted is text even when it looks like syntax, which is what keeps
   * `echo "rm -rf ~"` from reading as a deletion.
   */
  readonly quoted: boolean
}

/** One command in a line: the words between two separators. */
export interface Statement {
  readonly tokens: readonly Token[]
}

/** Characters that end a statement outright. */
const STATEMENT_END = new Set(['\n', '\r', ';'])

/** Whitespace that separates words without ending a statement. */
const WORD_END = new Set([' ', '\t'])

/**
 * Split a command line into statements, honouring quote state.
 *
 * A separator inside quotes is text, not a separator — that is the whole reason
 * this is a scan and not a `split()`. Quotes are tracked rather than interpreted:
 * `'` and `"` both open and close, and a backslash inside a double-quoted run
 * keeps the next character from ending it, which covers the escapes that matter
 * for finding where quotes stop.
 * @param command - the command line as the caller wrote it.
 * @returns one entry per statement, in order; empty statements are dropped.
 */
export function splitStatements(command: string): Statement[] {
  const statements: Statement[] = []
  let tokens: Token[] = []
  let text = ''
  let quoted = false
  let quote: '"' | "'" | undefined
  let previous = ''

  const endWord = (): void => {
    if (text !== '' || quoted) tokens.push({ text, quoted })
    text = ''
    quoted = false
  }
  const endStatement = (): void => {
    endWord()
    if (tokens.length > 0) statements.push({ tokens })
    tokens = []
  }

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] as string
    if (quote !== undefined) {
      if (character === quote) {
        quote = undefined
        previous = character
        continue
      }
      if (character === '\\' && quote === '"' && index + 1 < command.length) {
        text += command[index + 1] as string
        index += 1
        previous = character
        continue
      }
      text += character
      previous = character
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      if (text === '') quoted = true
      previous = character
      continue
    }
    if (WORD_END.has(character)) {
      endWord()
      continue
    }
    if (STATEMENT_END.has(character)) {
      endStatement()
      previous = character
      continue
    }
    // A redirect binds the words around it into one statement, so the `&` of
    // `2>&1` is not read as the start of a second command.
    if (character === '&' && previous !== '>') {
      if (command[index + 1] === '&') index += 1
      endStatement()
      previous = character
      continue
    }
    if (character === '|') {
      if (command[index + 1] === '|') index += 1
      endStatement()
      previous = character
      continue
    }
    if (character === '>' || character === '<') {
      endWord()
      previous = character
      continue
    }
    text += character
    previous = character
  }
  endStatement()
  return statements
}

/** The command-line verbs that remove things, by dialect. */
const DELETE_VERBS: ReadonlySet<string> = new Set([
  // POSIX
  'rm', 'rmdir', 'shred',
  // PowerShell (and the aliases it ships)
  'remove-item', 'ri', 'rd', 'del', 'erase',
])

/**
 * Tokens that may precede the verb without making the statement something else.
 *
 * `sudo rm -rf /` is a deletion whose verb is not the first word; `echo rm -rf ~`
 * is not a deletion at all, and requiring every preceding word to be one of
 * these is what tells the two apart.
 */
const INVOCATION_PREFIXES: ReadonlySet<string> = new Set([
  'sudo', 'doas', 'command', 'exec', 'nohup', 'time', 'builtin',
])

/** Verbs whose flags are written `/s`, `/f`, `/q` rather than `-…`. */
const CMD_STYLE_VERBS: ReadonlySet<string> = new Set(['rd', 'rmdir', 'del', 'erase'])

/**
 * Parameter names that consume the word after them.
 *
 * The value is not an operand — `-ErrorAction SilentlyContinue` must not be read
 * as two things being deleted — except for the two that hold the path, which are
 * operands in every sense that matters here.
 */
const VALUE_PARAMETERS: ReadonlySet<string> = new Set([
  '-erroraction', '-ea', '-filter', '-include', '-exclude', '-credential',
  '-depth', '-stream', '-attributes', '-confirm',
])

/** The two parameters that *are* the operand. */
const PATH_PARAMETERS: ReadonlySet<string> = new Set(['-path', '-literalpath'])

/** Letters a bundled short flag may be built from, as in `-rf` or `-Rfv`. */
const BUNDLE_LETTERS = /^[rfvnidsqzx]+$/

/** A single-letter word in a path is a flag only for the verbs that write them so. */
const CMD_FLAG = /^\/[A-Za-z]$/

/** One deletion as the scanner read it: enough for any rule to judge. */
export interface Deletion {
  /** The verb, lowercased, with any directory prefix removed. */
  readonly verb: string
  /** The operand words, in order, with quotes removed. */
  readonly targets: readonly string[]
  /** `-Recurse`/`-r`/`-R`/`/s` was present. */
  readonly recursive: boolean
  /** `-Force`/`-f`/`/f` was present. */
  readonly force: boolean
  /** `-WhatIf` was present: the statement is a dry run and removes nothing. */
  readonly dry: boolean
}

/**
 * The command name in a word, with the noise a shell allows around it removed.
 * `/bin/rm`, `./rm` and `rm` are one verb; so are `Remove-Item` and
 * `Microsoft.PowerShell.Management\Remove-Item`.
 * @param word - the word as written.
 * @returns the lowercased command name.
 */
function verbOf(word: string): string {
  const lastSeparator = Math.max(word.lastIndexOf('/'), word.lastIndexOf('\\'))
  const name = lastSeparator === -1 ? word : word.slice(lastSeparator + 1)
  return name.replace(/\.(?:exe|cmd|bat|ps1)$/i, '').toLowerCase()
}

/**
 * Read one statement as a deletion, when it is one.
 *
 * A statement is a deletion when its first word is a known verb, or when every
 * word before the first known verb is an invocation prefix or a flag. Anything
 * else — `echo rm -rf ~`, `xargs rm -rf` — is not read as a deletion, which is
 * the conservative direction: an unread deletion is a miss, not an accusation.
 * @param statement - one statement from {@link splitStatements}.
 * @returns the deletion, or `undefined` when the statement does not delete.
 */
export function readDeletion(statement: Statement): Deletion | undefined {
  const { tokens } = statement
  let verbIndex = -1
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] as Token
    if (token.quoted) return undefined
    const verb = verbOf(token.text)
    if (DELETE_VERBS.has(verb)) {
      verbIndex = index
      break
    }
    const isPrefix = INVOCATION_PREFIXES.has(verb) || token.text.startsWith('-')
    if (!isPrefix) return undefined
  }
  if (verbIndex === -1) return undefined

  const verb = verbOf((tokens[verbIndex] as Token).text)
  const cmdStyle = CMD_STYLE_VERBS.has(verb)
  const targets: string[] = []
  let recursive = false
  let force = false
  let dry = false

  for (let index = verbIndex + 1; index < tokens.length; index += 1) {
    const token = tokens[index] as Token
    const word = token.text
    if (token.quoted) {
      targets.push(word)
      continue
    }
    if (cmdStyle && CMD_FLAG.test(word)) {
      const letter = word.slice(1).toLowerCase()
      if (letter === 's') recursive = true
      if (letter === 'f') force = true
      continue
    }
    if (word.startsWith('-') && word.length > 1) {
      const parameter = word.toLowerCase()
      if (parameter === '-whatif' || parameter === '-dry-run') {
        dry = true
        continue
      }
      if (parameter === '-recurse' || parameter === '-recursive') {
        recursive = true
        continue
      }
      if (parameter === '-force') {
        force = true
        continue
      }
      const bundle = parameter.slice(1)
      if (bundle.length <= 4 && BUNDLE_LETTERS.test(bundle)) {
        if (bundle.includes('r')) recursive = true
        if (bundle.includes('f')) force = true
        continue
      }
      if (PATH_PARAMETERS.has(parameter)) {
        const value = tokens[index + 1]
        if (value !== undefined) {
          targets.push(value.text)
          index += 1
        }
        continue
      }
      if (VALUE_PARAMETERS.has(parameter)) {
        index += 1
        continue
      }
      continue
    }
    targets.push(word)
  }

  return { verb, targets, recursive, force, dry }
}

/**
 * Every deletion in a command line, in order.
 * @param command - the command line as the caller wrote it.
 * @returns the deletions the scanner could read.
 */
export function findDeletions(command: string): Deletion[] {
  const found: Deletion[] = []
  for (const statement of splitStatements(command)) {
    const deletion = readDeletion(statement)
    if (deletion !== undefined) found.push(deletion)
  }
  return found
}

/** `$name=value` or `$name=` — the PowerShell spelling, value attached. */
const POWERSHELL_ATTACHED = /^\$([A-Za-z_][A-Za-z0-9_]*)=/
/** `$name` with the `=` on the following word — the same assignment, spaced. */
const POWERSHELL_BARE = /^\$([A-Za-z_][A-Za-z0-9_]*)$/
/** `name=value` — the POSIX spelling, and cmd's once `set` precedes it. */
const PLAIN_ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=/
const CMD_SET = /^set$/i

/**
 * Assert that a word is a variable reference, and name the variable.
 *
 * `$home` and `${HOME}` are one variable; `$env:USERPROFILE` is not one this
 * answers, because it can be neither assigned nor shadowed — the rule that needs
 * it reads the word directly.
 * @param word - the operand word as written.
 * @returns the lowercased variable name, or `undefined`.
 */
export function variableName(word: string): string | undefined {
  const match = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(word)
  return match?.[1]?.toLowerCase()
}

/** The names a command assigns to, split by the spelling used. */
export interface Assignments {
  /**
   * Names assigned with PowerShell's spelling (`$name = …`, `$name=…`).
   *
   * The spelling is load-bearing, not cosmetic. In PowerShell an assignment to
   * an automatic variable *fails*: the name keeps the value the runtime gave it.
   * So a name in this set that is also a deletion operand is a collision — the
   * command deletes the reserved value, not the one the line appears to name.
   */
  readonly powershell: ReadonlySet<string>
  /**
   * Names assigned with the plain spelling (`name=…`, `set name=…`).
   *
   * In these dialects the assignment *works*, so the name is the author's own
   * variable and a later `$name` operand is their value rather than the
   * runtime's. That is what neutralises the home reading of a lowercase-name
   * operand: `home=/srv/scratch; rm -rf $home` is a cleanup, and reading it as
   * the home directory would be a false accusation.
   */
  readonly plain: ReadonlySet<string>
}

/**
 * Every name the command assigns to, split by spelling.
 *
 * A quoted word is never an assignment — `echo "$home = x"` is text — and a word
 * that only *reads* a variable is not one either, which is the distinction the
 * collision rule is built on.
 * @param command - the command line as the caller wrote it.
 * @returns the two name sets.
 */
export function readAssignments(command: string): Assignments {
  const powershell = new Set<string>()
  const plain = new Set<string>()
  for (const statement of splitStatements(command)) {
    const { tokens } = statement
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index] as Token
      if (token.quoted) continue
      const attached = POWERSHELL_ATTACHED.exec(token.text)
      if (attached?.[1] !== undefined) {
        powershell.add(attached[1].toLowerCase())
        continue
      }
      if (POWERSHELL_BARE.test(token.text) && tokens[index + 1]?.text === '=') {
        powershell.add(token.text.slice(1).toLowerCase())
        continue
      }
      const plainName = PLAIN_ASSIGNMENT.exec(token.text)
      if (plainName?.[1] !== undefined) {
        plain.add(plainName[1].toLowerCase())
        continue
      }
      if (CMD_SET.test(token.text)) {
        const set = PLAIN_ASSIGNMENT.exec(tokens[index + 1]?.text ?? '')
        if (set?.[1] !== undefined) plain.add(set[1].toLowerCase())
      }
    }
  }
  return { powershell, plain }
}
