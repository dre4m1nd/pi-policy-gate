#!/usr/bin/env bun
/**
 * Policy simulator runner.
 *
 * Loads a permission policy and the sample corpus, runs the offline
 * simulation, and prints the decision matrix, rule coverage, and detected
 * dead rules. With `--base <dir>` it additionally diffs decisions against a
 * second policy to catch unintended allow/deny changes.
 *
 * Usage:
 *   bun scripts/policy-simulator.ts [--policy <policy.jsonc>] [--corpus <corpus.json>] [--base <policy-dir>]
 *
 * The policy is loaded through PermissionManager by pointing it at a directory
 * containing `pi-permissions.jsonc`, which is exactly how the live extension
 * resolves global policy. This guarantees the simulation uses the same
 * evaluation path as the running gate.
 */
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { PermissionManager } from "../src/core/permission-manager.js"
import { runSimulation, diffDecisions, type SimulationReport, type SimulationSample } from "../src/governance/policy-simulator.js"

type Args = { policy: string; corpus: string; basePolicyDir: string | null };

function parseArgs(argv: string[]): Args {
  const args: Args = {
    policy: "config/config.example.json",
    corpus: "samples/policy-corpus.json",
    basePolicyDir: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--policy") args.policy = argv[++i];
    else if (arg === "--corpus") args.corpus = argv[++i];
    else if (arg === "--base") args.basePolicyDir = argv[++i];
  }
  return args;
}

function loadCorpus(path: string): SimulationSample[] {
  const raw = JSON.parse(readFileSync(resolve(path), "utf-8")) as { samples: SimulationSample[] };
  return raw.samples;
}

function makePolicyDir(policyPath: string): string {
  const dir = mkdtempSync(join(tmpdir(), "pi-policy-gate-"));
  const target = join(dir, "pi-permissions.jsonc");
  writeFileSync(target, readFileSync(resolve(policyPath), "utf-8"), "utf-8");
  return dir;
}

function printReport(label: string, report: SimulationReport): void {
  console.log(`\n=== ${label} (policy ${report.policyVersion}) ===`);
  console.log("Decision matrix:");
  for (const sample of report.samples) {
    const mark = sample.passed ? "PASS" : "FAIL";
    const note = sample.note ? `  # ${sample.note}` : "";
    console.log(
      `  [${mark}] #${sample.index} ${sample.toolName} -> expected=${sample.expected} actual=${sample.actual}`
      + `${sample.matchedPattern ? ` (${sample.matchedPattern})` : ""}${note}`,
    );
  }
  console.log(`Summary: ${report.summary.passed}/${report.summary.total} passed, coverage ${report.summary.coverage}`);
  if (report.deadRules.length > 0) {
    console.log("Dead rules (never matched):");
    for (const rule of report.deadRules) {
      console.log(`  - ${rule.category}.${rule.pattern} = ${rule.state}`);
    }
  }
}

const args = parseArgs(Bun.argv.slice(2));
const samples = loadCorpus(args.corpus);

const policyDir = makePolicyDir(args.policy);
const manager = new PermissionManager({
  globalConfigPath: join(policyDir, "pi-permissions.jsonc"),
  agentsDir: join(policyDir, "agents"),
});

const report = runSimulation(manager, samples);
printReport("SIMULATION", report);

let failed = false;
if (report.summary.failed > 0) {
  failed = true;
  console.log(`\nRESULT: FAIL — ${report.summary.failed} sample(s) did not match expected decisions.`);
} else {
  console.log("\nRESULT: PASS — all samples match expected decisions.");
}

if (args.basePolicyDir) {
  const baseReport = runSimulation(
    new PermissionManager({
      globalConfigPath: join(resolve(args.basePolicyDir), "pi-permissions.jsonc"),
      agentsDir: join(resolve(args.basePolicyDir), "agents"),
    }),
    samples,
  );
  const diff = diffDecisions(baseReport, report);
  const changed = diff.filter((entry) => entry.changed);
  console.log(`\n=== DECISION DIFF (base ${baseReport.policyVersion} -> ${report.policyVersion}) ===`);
  if (changed.length === 0) {
    console.log("No decisions changed between policies.");
  } else {
    for (const entry of changed) {
      console.log(`  #${entry.index} ${entry.toolName}: ${entry.baseDecision} -> ${entry.nextDecision}${entry.note ? `  # ${entry.note}` : ""}`);
    }
  }
}

rmSync(policyDir, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
