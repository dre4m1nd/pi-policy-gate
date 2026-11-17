import { writeFileSync } from "node:fs";

import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

import { AuditLedger, type AuditEntry } from "./audit-ledger.js";

/**
 * `/audit` command.
 *
 *   /audit             show the most recent decisions (newest first)
 *   /audit export <path>   write all recent entries as JSONL to <path>
 *
 * The command is read-only with respect to the permission gate: it only
 * inspects and exports the ledger. Export is the intended way to hand audit
 * records to CI or post-hoc review without polluting the transcript.
 */

const DEFAULT_RECENT_LIMIT = 20;

function formatEntry(entry: AuditEntry): string {
  const subject = entry.subject ? ` "${entry.subject}"` : "";
  const pattern = entry.matchedPattern ? ` (${entry.matchedPattern})` : "";
  const approval = entry.humanApproval ? " [approved]" : "";
  return `${entry.timestamp}  ${entry.decision.padEnd(5)} ${entry.toolName}${subject}${pattern}${approval}  v=${entry.policyVersion}`;
}

export function createAuditCommandHandler(
  ledger: AuditLedger,
  recentLimit: number = DEFAULT_RECENT_LIMIT,
): (args: string, ctx: ExtensionCommandContext) => Promise<void> {
  return async (args: string, ctx: ExtensionCommandContext) => {
    if (!ctx.hasUI) {
      ctx.ui.notify("/audit requires interactive TUI mode.", "warning");
      return;
    }

    const parts = args.trim().split(/\s+/).filter(Boolean);
    const subcommand = parts[0] ?? "";

    if (subcommand === "export") {
      const target = parts[1];
      if (!target) {
        ctx.ui.notify("Usage: /audit export <path>", "warning");
        return;
      }
      const entries = ledger.readRecent(recentLimit * 50);
      if (entries.length === 0) {
        ctx.ui.notify("No audit records found.", "info");
        return;
      }
      try {
        writeFileSync(target, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, "utf-8");
        ctx.ui.notify(`Exported ${entries.length} audit records to ${target}`, "info");
      } catch (error) {
        ctx.ui.notify(`Failed to export audit records: ${(error as Error).message}`, "error");
      }
      return;
    }

    const entries = ledger.readRecent(recentLimit);
    if (entries.length === 0) {
      ctx.ui.notify("No audit records found. Permission decisions will be logged here.", "info");
      return;
    }

    const counts = entries.reduce<Record<string, number>>((acc, entry) => {
      acc[entry.decision] = (acc[entry.decision] ?? 0) + 1;
      return acc;
    }, {});
    const summary = entries.length
      ? `Audit: ${entries.length} recent decisions `
        + `(${Object.entries(counts).map(([decision, count]) => `${decision}:${count}`).join(", ")}) `
        + `from ${new Set(entries.map((entry) => entry.policyVersion)).size} policy version(s)`
      : "Audit: no decisions";

    ctx.ui.notify(summary, "info");
    for (const entry of entries) {
      ctx.ui.notify(formatEntry(entry), "info");
    }
  };
}
