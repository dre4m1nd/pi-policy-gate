import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PermissionManager } from "../src/core/permission-manager.js"
import { diffDecisions, runSimulation, type SimulationSample } from "../src/governance/policy-simulator.js"

function makeManager(policyJson: string): { manager: PermissionManager; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "pi-policy-gate-sim-"));
  writeFileSync(join(dir, "pi-permissions.jsonc"), policyJson, "utf-8");
  return {
    manager: new PermissionManager({
      globalConfigPath: join(dir, "pi-permissions.jsonc"),
      agentsDir: join(dir, "agents"),
    }),
    dir,
  };
}

const basePolicy = JSON.stringify({
  defaultPolicy: { tools: "ask", bash: "ask", mcp: "ask", skills: "ask", special: "ask" },
  tools: { read: "allow", write: "deny" },
  bash: { "git status": "allow" },
  mcp: {},
  skills: {},
  special: { doom_loop: "deny" },
});

const samples: SimulationSample[] = [
  { toolName: "read", input: { path: "src/index.ts" }, expected: "allow", note: "read allow" },
  { toolName: "write", input: { path: "src/new.ts" }, expected: "deny", note: "write deny" },
  { toolName: "edit", input: { path: "src/index.ts" }, expected: "ask", note: "default tools ask" },
  { toolName: "bash", input: { command: "git status" }, expected: "allow", note: "git status allow" },
  { toolName: "bash", input: { command: "rm -rf /" }, expected: "ask", note: "default bash ask" },
  { toolName: "doom_loop", input: {}, expected: "deny", note: "doom_loop deny" },
];

export function runPolicySimulatorTests(): void {
  const { manager, dir } = makeManager(basePolicy);
  try {
    const report = runSimulation(manager, samples);

    assert.equal(report.summary.total, 6);
    assert.equal(report.summary.passed, 6, "all samples should match expected decisions");
    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.coverage, 1);
    assert.ok(report.policyVersion.startsWith("v1-"));

    // Every sample records the matched pattern when one exists.
    const readSample = report.samples[0];
    assert.equal(readSample.matchedPattern, "read");
    const bashSample = report.samples[3];
    assert.equal(bashSample.matchedPattern, "git status");

    // Dead-rule detection: the read/write/git/doom_loop rules are exercised,
    // but there is no skill/mcp rule to be dead, and defaultPolicy is excluded.
    const deadPatterns = report.deadRules.map((rule) => `${rule.category}.${rule.pattern}`);
    assert.ok(!deadPatterns.some((pattern) => pattern.startsWith("defaultPolicy")), "defaultPolicy excluded from dead rules");
    assert.ok(!deadPatterns.includes("tools.read"), "tools.read is exercised, not dead");
    assert.ok(!deadPatterns.includes("bash.git status"), "bash.git status is exercised, not dead");

    console.log("[PASS] runSimulation produces a passing decision matrix with coverage");

    // A sample that expects the wrong decision must be reported as failed.
    const wrongSamples: SimulationSample[] = [
      ...samples,
      { toolName: "read", input: { path: "x.ts" }, expected: "deny", note: "intentionally wrong" },
    ];
    const failingReport = runSimulation(manager, wrongSamples);
    assert.equal(failingReport.summary.failed, 1, "wrong expectation is flagged");
    assert.equal(failingReport.samples[6].passed, false);
    console.log("[PASS] runSimulation flags mismatched expectations");

    // Decision diff: changing a rule flips the decision for the affected sample.
    const nextPolicy = JSON.stringify({
      defaultPolicy: { tools: "ask", bash: "ask", mcp: "ask", skills: "ask", special: "ask" },
      tools: { read: "deny", write: "deny" },
      bash: { "git status": "allow" },
      mcp: {},
      skills: {},
      special: { doom_loop: "deny" },
    });
    const nextDir = mkdtempSync(join(tmpdir(), "pi-policy-gate-sim2-"));
    try {
      writeFileSync(join(nextDir, "pi-permissions.jsonc"), nextPolicy, "utf-8");
      const nextManager = new PermissionManager({
        globalConfigPath: join(nextDir, "pi-permissions.jsonc"),
        agentsDir: join(nextDir, "agents"),
      });
      const diff = diffDecisions(report, runSimulation(nextManager, samples));
      const changedRead = diff.find((entry) => entry.toolName === "read");
      assert.ok(changedRead, "read decision should be present in diff");
      assert.equal(changedRead.changed, true, "read decision changed allow -> deny");
      assert.equal(changedRead.baseDecision, "allow");
      assert.equal(changedRead.nextDecision, "deny");
      const unchangedWrite = diff.find((entry) => entry.toolName === "write");
      assert.ok(unchangedWrite, "write decision should be present in diff");
      assert.equal(unchangedWrite.changed, false, "write decision unchanged");
      console.log("[PASS] diffDecisions reports flipped decisions between policies");
    } finally {
      rmSync(nextDir, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("policy-simulator tests passed.");
}

runPolicySimulatorTests();
