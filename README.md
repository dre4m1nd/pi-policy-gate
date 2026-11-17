<div align="center">

# pi-policy-gate

**A versioned, auditable permission policy engine for the [Pi](https://github.com/earendil-works/pi) coding agent.**

Every tool call an agent makes (bash, file read/write, MCP, skills, special
operations) passes through a deterministic gate. This project turns that gate
from a runtime-only switch into something you can **version, audit, and
regression-test** offline.

</div>

## Why

Coding agents run with the user's full authority. A prompt injection, a
misdirected model, or a careless rule can delete a repo, push to the wrong
branch, or exfiltrate a credential. The fix is a deterministic permission gate
in front of every tool call — but a gate you cannot observe is a gate you
cannot trust. pi-policy-gate adds the three things that make a permission
policy verifiable:

- **Versioning** — every decision is bound to a content hash of the effective
  policy, so you can always answer "which policy produced this decision?".
- **Audit** — every decision is recorded as an append-only, redacted JSONL
  record, retrievable from the TUI or exported for CI.
- **Simulation** — a fixed corpus of tool calls is evaluated against a policy
  to produce a decision matrix, rule coverage, dead-rule detection, and a
  decision diff between two policy versions.

pi-policy-gate is the successor of
[pi-permission-system](https://github.com/MasuRii/pi-permission-system): the
deterministic evaluation core (wildcard matching, last-match-wins, layered
config) is carried over unchanged, and the governance layer is built on top of
it. The extension id, debug log name, and permission-request event channel
keep the `pi-permission-system` identifiers so an existing installation
upgrades in place without breaking configured consumers.

## How it works

The gate is a three-stage pure pipeline. The live handler and the offline
simulator share the exact same evaluation path, so a passing simulation means
the running gate will agree with the expected decisions.

```
tool call (tool, command/args)
        │
        ▼
┌─────────────────────┐
│  1. resolve         │  effective policy for the agent + its version (content hash)
│  2. evaluate        │  match against compiled rules (last-match-wins)
│  3. decide          │  allow / deny / ask
└─────────────────────┘
        │
        ├─ allow ───────────────► execute
        ├─ deny  ───────────────► block
        └─ ask   ───────────────► prompt the user, then allow / deny
        │
        ▼
   audit ledger (append-only JSONL, redacted, tagged with policyVersion)
```

## What it adds over the base

| Area | Base (pi-permission-system) | pi-policy-gate |
| --- | --- | --- |
| Evaluation core | Wildcard matching, layered config, fail-closed fallback | unchanged |
| Policy versioning | none | content hash of the effective policy, attached to every decision |
| Audit | review entries in session history | append-only decision ledger with secret redaction |
| `/audit` | none | show recent decisions or export to a file |
| Offline validation | none | policy simulator: decision matrix, coverage, dead rules, diff |

## Bash subcommand rules

An exact bash pattern is still exact (`"git status"` matches only `git status`).
To gate a **subcommand** regardless of its arguments, prefix the pattern with
`cmd:`:

```jsonc
{
  "bash": {
    "git *": "ask",
    "cmd:git push": "deny",
    "cmd:git status": "allow"
  }
}
```

`cmd:git push` matches `git push`, `git push --force origin main`,
`FOO=bar git push`, `/usr/bin/git push`, and `git.exe push`; it does not match
`git status`, `git pushx`, or `echo git push`. Rules participate in the same
last-match-wins ordering as every other bash rule, so declare broader wildcard
rules first and specific `cmd:` rules later.

## Install

```bash
pi install git:github.com/<you>/pi-policy-gate
```

Or from a local checkout:

```bash
git clone https://github.com/MasuRii/pi-policy-gate.git
cd pi-policy-gate
bun install
pi install .
```

The extension registers two slash commands:

- `/permission-system` — configure debug logging and yolo-mode behavior.
- `/audit` — show the most recent decisions, or `/audit export <path>` to
  write them as JSONL for CI or post-hoc review.

## The three pillars

### 1. Policy versioning

`src/policy-version.ts` computes a short SHA-256 content hash of the
**effective** policy (the result of layering global, project, agent, and
project-agent permissions). The canonical form sorts every rule map by key, so
the same set of rules always yields the same version regardless of file
formatting or key order. Any change to an effective rule changes the version.

Every audit record carries the version it was decided under, so decisions are
traceable. `diffPolicies()` produces a human-readable add/remove/change
report between two versions.

### 2. Audit decision ledger

`src/audit-ledger.ts` appends one JSONL line per decision to
`~/.pi/agent/audit/decisions-<date>.jsonl`. Each record contains the
policy version, tool, source, matched rule, decision, and a **redacted**
subject (command or resource). Redaction targets common credential shapes
(provider keys, bearer tokens, key=value secrets, long opaque tokens) while
leaving ordinary commands and paths intact.

Design guarantee: the ledger is a **side effect**. A decision is never blocked
or altered because logging failed — a missing record means the decision path
did not reach the ledger, not that logging was silently skipped.

### 3. Policy simulator

`src/policy-simulator.ts` + `scripts/policy-simulator.ts` run a fixed corpus
(`samples/policy-corpus.json`) against a policy and report:

- **Decision matrix** — each sample's expected vs actual decision.
- **Rule coverage** — how often each rule is exercised.
- **Dead rules** — rules that never matched any sample (written but never
  effective). `defaultPolicy` entries are excluded: they are fallback
  semantics, not rules to be exercised.
- **Decision diff** — which samples changed decision between two policies, so
  a policy edit cannot silently flip an allow to a deny (or vice versa).

```bash
# run the reference policy against the reference corpus
bun run simulate

# compare two policies
bun scripts/policy-simulator.ts --policy policy-a.jsonc --base ./policy-b-dir
```

## Engineering decisions

| Question | Decision | Rationale |
| --- | --- | --- |
| Config parse error | **fail-closed**: fall back to `ask` | A broken policy must not silently allow everything. |
| Rule conflict | **last-match-wins** (from base) | Preserves the base's proven semantics; the simulator surfaces when a later rule overrides an earlier one. |
| Audit write failure | **decision unaffected**, log a warning | The gate must never be bypassed because logging is down. |
| Regex injection | pattern length cap + escaping (from base) | Oversized/untrusted patterns cannot cause catastrophic backtracking. |
| Dead-rule detection | excludes `defaultPolicy` | Defaults are fallbacks, not rules to be "exercised". |
| Redaction | conservative, targeted | Remove credential shapes without mangling normal commands/paths. |

## Layout

```
src/
  policy-version.ts     canonical policy + content hash + diff
  policy-pipeline.ts    pure resolve → evaluate → decide pipeline
  audit-ledger.ts       append-only decision ledger + redaction
  audit-command.ts      /audit command handler
  bash-command.ts       cmd: subcommand rule compiler
  policy-simulator.ts   offline simulation, coverage, dead rules, diff
  permission-manager.ts evaluation core (from base; + getEffectivePolicy)
  index.ts              extension wiring: tool_call gate + commands
samples/
  policy-corpus.json    reference decision corpus
scripts/
  policy-simulator.ts   simulator CLI runner
tests/                  unit + table-driven regression tests
```

## Testing

```bash
bun install
bun run typecheck
bun run test        # full suite
bun run simulate    # offline policy regression
```

The suite includes table-driven tests for each new module (policy versioning,
audit redaction/ledger, the evaluation pipeline, and the simulator).

> Note: `tests/config-preservation-red.test.ts` is an Issue #31 regression
> suite. Its symlink-preservation case is guarded by an explicit skip when the
> platform cannot create file symlinks (Windows without Developer Mode / an
> elevated shell, where `symlinkSync` throws `EPERM`); on Linux and macOS the
> case runs and passes, confirming that saving through a symlinked
> `config.json` writes to the target and leaves the link intact.

## License

MIT. Derived from [pi-permission-system](https://github.com/MasuRii/pi-permission-system) (MIT).
