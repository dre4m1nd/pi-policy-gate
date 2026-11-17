import {
  compileWildcardPattern,
  type CompiledWildcardPattern,
} from "./wildcard-matcher.js";

/**
 * Subcommand-level bash rules.
 *
 * A bash rule whose pattern starts with `cmd:` matches a command *prefix* at a
 * token boundary, so arguments do not affect the match:
 *
 *   "cmd:git push"    matches `git push`, `git push --force origin main`,
 *                     `FOO=bar git push`, `/usr/bin/git push`, `git.exe push`
 *   "cmd:git status"  matches `git status`, `git status --short`
 *
 * and does not match `git pushx`, `git status`, or `echo git push`.
 *
 * Rules without the `cmd:` marker keep the existing wildcard semantics, so
 * this is fully opt-in. Subcommand rules participate in the same
 * last-match-wins ordering as every other bash rule: declare broader wildcard
 * rules first and more specific `cmd:` rules later.
 */

const COMMAND_RULE_PREFIX = "cmd:";

export function isCommandRule(pattern: string): boolean {
  return pattern.startsWith(COMMAND_RULE_PREFIX);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function tokenizePrefix(prefix: string): string[] {
  return prefix.trim().split(/\s+/).filter((token) => token.length > 0);
}

/**
 * Compile a bash rule into the shared compiled-pattern shape.
 *
 * `cmd:` rules become a prefix regex with three allowances:
 * - optional leading environment assignments (`FOO=bar`)
 * - an optional path prefix on the executable (`/usr/bin/git`)
 * - an optional `.exe` suffix on the executable (Windows)
 *
 * The match ends at a token boundary (whitespace, end of string, or a shell
 * separator) so `cmd:git push` cannot match `git pushx`.
 */
export function compileCommandPattern<TState>(
  pattern: string,
  state: TState,
): CompiledWildcardPattern<TState> {
  if (!isCommandRule(pattern)) {
    return compileWildcardPattern(pattern, state);
  }

  const tokens = tokenizePrefix(pattern.slice(COMMAND_RULE_PREFIX.length));
  if (tokens.length === 0) {
    return { pattern, state, regex: /$^/ };
  }

  const [firstToken, ...restTokens] = tokens;
  const executablePattern = `(?:[^\\s;|&]*[\\\\/])?${escapeRegExp(firstToken)}(?:\\.exe)?`;
  const restPattern = restTokens.map((token) => `\\s+${escapeRegExp(token)}`).join("");
  const regex = new RegExp(
    `^\\s*(?:[A-Za-z_][A-Za-z0-9_]*=\\S*\\s+)*${executablePattern}${restPattern}(?=\\s|$|[;&|])`,
    "s",
  );

  return { pattern, state, regex };
}

export function compileCommandPatternEntries<TState>(
  entries: Iterable<readonly [string, TState]>,
): CompiledWildcardPattern<TState>[] {
  return Array.from(entries, ([pattern, state]) => compileCommandPattern(pattern, state));
}

export function compileCommandPatterns<TState>(
  patterns: Record<string, TState>,
): CompiledWildcardPattern<TState>[] {
  return compileCommandPatternEntries(Object.entries(patterns));
}
