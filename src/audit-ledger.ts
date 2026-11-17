import { appendFileSync, mkdirSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { getAgentDir } from "@earendil-works/pi-coding-agent";

import type { PermissionState } from "./types.js";

/**
 * Audit decision ledger.
 *
 * Every permission decision is appended as one JSONL line. The ledger is an
 * *append-only* side effect: a decision must never be blocked or altered
 * because logging failed. This keeps the permission gate itself available even
 * if the audit store is unavailable, and keeps the audit honest (a missing
 * record means the decision path did not reach the ledger, not that logging
 * was skipped silently).
 */

export type AuditDecision = "allow" | "deny" | "ask";

export type AuditEntry = {
  id: string;
  timestamp: string;
  policyVersion: string;
  toolName: string;
  source: "tool" | "bash" | "mcp" | "skill" | "special" | "default";
  state: PermissionState;
  decision: AuditDecision;
  matchedPattern?: string;
  target?: string;
  /** Redacted command or path summary. */
  subject?: string;
  /** Whether a human approval was involved (ask paths). */
  humanApproval?: boolean;
  /** Session identifier when available. */
  sessionId?: string;
};

export const AUDIT_DIR_ENV_KEY = "PI_POLICY_GATE_AUDIT_DIR";

export function defaultAuditDir(): string {
  const override = process.env[AUDIT_DIR_ENV_KEY]?.trim();
  if (override) {
    return override;
  }
  const agentDir = process.env.PI_CODING_AGENT_DIR?.trim() || getAgentDir();
  return join(agentDir, "audit");
}

export function auditFilePathForDate(dir: string, date: Date = new Date()): string {
  const iso = date.toISOString().slice(0, 10);
  return join(dir, `decisions-${iso}.jsonl`);
}

const SECRET_PATTERNS: Array<{ pattern: RegExp; replacement: string | ((match: string) => string) }> = [
  // Provider / API style keys: sk-xxxx, xoxb-xxxx, ghp_xxxx, etc.
  { pattern: /\b(sk|pk|xox[baprs]|ghp|gho|ghs|github_pat)_[A-Za-z0-9_-]{8,}\b/g, replacement: "[REDACTED_KEY]" },
  // Bearer tokens in headers.
  { pattern: /\bBearer\s+[A-Za-z0-9._~+/-]+=*/g, replacement: "Bearer [REDACTED_TOKEN]" },
  // Common credential key=value pairs (keep the key name for context).
  { pattern: /\b(api[_-]?key|apikey|token|secret|password|passwd|authorization|auth)\b(\s*[:=]\s*)("?)([A-Za-z0-9._~+/-]{6,})\3/gi, replacement: "$1$2$3[REDACTED]$3" },
  // Long opaque tokens (JWT-ish / base64 / hex) — keep a short prefix for debugging.
  { pattern: /\b[A-Za-z0-9_-]{32,}\b/g, replacement: (match: string) => `${match.slice(0, 6)}[REDACTED_LONG]` },
];

/**
 * Apply secret redaction to a free-form subject string before it is written
 * to the ledger. Redaction is deliberately conservative: it targets common
 * credential shapes while leaving ordinary commands and paths intact.
 */
export function redactSubject(subject: string): string {
  let result = subject;
  for (const { pattern, replacement } of SECRET_PATTERNS) {
    result = typeof replacement === "function"
      ? result.replace(pattern, replacement)
      : result.replace(pattern, replacement);
  }
  return result;
}

export class AuditLedger {
  private readonly dir: string;

  constructor(dir: string = defaultAuditDir()) {
    this.dir = dir;
  }

  get directory(): string {
    return this.dir;
  }

  /** Append a single audit entry. Never throws: logging failures are swallowed. */
  append(entry: Omit<AuditEntry, "id" | "timestamp"> & { id?: string }): void {
    try {
      mkdirSync(this.dir, { recursive: true });
      const full: AuditEntry = {
        id: entry.id ?? randomUUID(),
        timestamp: new Date().toISOString(),
        ...entry,
      };
      appendFileSync(auditFilePathForDate(this.dir), `${JSON.stringify(full)}\n`, "utf-8");
    } catch {
      // Audit is a side effect. A failed write must not change the decision.
    }
  }

  /** Read all entries for a given date, oldest first. */
  read(date: Date = new Date()): AuditEntry[] {
    const file = auditFilePathForDate(this.dir, date);
    if (!existsSync(file)) {
      return [];
    }
    const entries: AuditEntry[] = [];
    for (const line of readFileSync(file, "utf-8").split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      try {
        entries.push(JSON.parse(trimmed) as AuditEntry);
      } catch {
        // Skip malformed lines rather than failing the whole read.
      }
    }
    return entries;
  }

  /** Return the most recent N entries across the ledger directory, newest first. */
  readRecent(limit: number): AuditEntry[] {
    const files = existsSync(this.dir)
      ? readdirSync(this.dir)
        .filter((name) => name.startsWith("decisions-") && name.endsWith(".jsonl"))
        .sort()
      : [];
    const collected: AuditEntry[] = [];
    for (const file of files) {
      collected.push(...this.read(new Date(file.slice("decisions-".length, -".jsonl".length) + "T00:00:00Z")));
    }
    return collected.slice(-limit).reverse();
  }
}
