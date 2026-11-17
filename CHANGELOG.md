# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-11-17

First standalone release of pi-policy-gate: a versioned, auditable permission
policy engine for the Pi coding agent.

### Added

- **Policy versioning** — `computePolicyVersion()` hashes the canonical
  (sorted-key) form of the effective policy; `diffPolicies()` reports
  added/removed/changed rules between two versions. Every decision is tagged
  with the policy version that produced it.
- **Audit decision ledger** — append-only, redacted JSONL records with
  `redactSubject()` targeting common credential shapes. Audit writes are side
  effects and never alter a decision. `/audit` shows recent decisions or
  exports them for CI and post-hoc review.
- **Policy simulator** — runs a fixed corpus against an effective policy to
  produce a decision matrix, rule coverage, dead-rule detection, and a decision
  diff between two policies. Shares the evaluation path with the live gate.
- **`cmd:` subcommand bash rules** — a rule prefixed with `cmd:` matches a
  command prefix at a token boundary, so arguments, environment assignments,
  and path/`.exe` prefixes do not affect the match.
- `PermissionManager.getEffectivePolicy()`, exposing the merged, layered policy
  for versioning and simulation.
- Regression suites for the new modules: policy versioning/diff, audit
  redaction and ledger, the evaluation pipeline, the simulator, `cmd:` rule
  compilation, and multiline/ReDoS wildcard behavior.

### Changed

- Organized the source into feature folders: `core` (evaluation), `governance`
  (versioning, audit, simulation), `extension` (wiring and runtime), `ui`
  (dialogs and modals), and `prompt` (system/skill prompt sanitizing).
- Renamed the user-visible identifiers from `pi-permission-system` to
  `pi-policy-gate`: the extension id (status key), the debug log file, and the
  permission-request event channel.
