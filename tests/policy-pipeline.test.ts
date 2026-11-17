import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PermissionManager } from "../src/permission-manager.js";
import { describeSubject, evaluateToolCall } from "../src/policy-pipeline.js";

function makeManager(policyJson: string): { manager: PermissionManager; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "pi-policy-gate-pipe-"));
  writeFileSync(join(dir, "pi-permissions.jsonc"), policyJson, "utf-8");
  return {
    manager: new PermissionManager({
      globalConfigPath: join(dir, "pi-permissions.jsonc"),
      agentsDir: join(dir, "agents"),
    }),
    dir,
  };
}

export function runPolicyPipelineTests(): void {
  const policy = JSON.stringify({
    defaultPolicy: { tools: "ask", bash: "ask", mcp: "ask", skills: "ask", special: "ask" },
    tools: { read: "allow", write: "deny" },
    bash: { "git *": "ask" },
    mcp: {},
    skills: {},
    special: {},
  });
  const { manager, dir } = makeManager(policy);
  try {
    const cases: Array<{ name: string; run: () => void }> = [
      {
        name: "evaluateToolCall maps allow state to allow decision with matched rule",
        run: () => {
          const decision = evaluateToolCall(manager, "read", { path: "src/index.ts" });
          assert.equal(decision.state, "allow");
          assert.equal(decision.decision, "allow");
          assert.equal(decision.matchedPattern, "read");
          assert.equal(decision.source, "tool");
          assert.ok(decision.policyVersion.startsWith("v1-"));
        },
      },
      {
        name: "evaluateToolCall maps deny state to deny decision",
        run: () => {
          const decision = evaluateToolCall(manager, "write", { path: "src/new.ts" });
          assert.equal(decision.state, "deny");
          assert.equal(decision.decision, "deny");
          assert.equal(decision.matchedPattern, "write");
        },
      },
      {
        name: "evaluateToolCall maps ask state to ask decision for bash",
        run: () => {
          const decision = evaluateToolCall(manager, "bash", { command: "git push" });
          assert.equal(decision.state, "ask");
          assert.equal(decision.decision, "ask");
          assert.equal(decision.matchedPattern, "git *");
          assert.equal(decision.source, "bash");
        },
      },
      {
        name: "describeSubject prefers the command for bash",
        run: () => {
          const decision = evaluateToolCall(manager, "bash", { command: "git status" });
          assert.equal(describeSubject(decision), "git status");
        },
      },
      {
        name: "describeSubject falls back to the target when no command",
        run: () => {
          const decision = evaluateToolCall(manager, "read", { path: "src/index.ts" });
          assert.equal(describeSubject(decision), "read");
        },
      },
    ];

    for (const testCase of cases) {
      assert.doesNotThrow(() => testCase.run(), testCase.name);
      console.log(`[PASS] ${testCase.name}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("policy-pipeline tests passed.");
}

runPolicyPipelineTests();
