import assert from "node:assert/strict";

import {
  computePolicyVersion,
  diffPolicies,
  toCanonicalPolicy,
} from "../src/policy-version.js";
import type { GlobalPermissionConfig } from "../src/types.js";

const basePolicy: GlobalPermissionConfig = {
  defaultPolicy: { tools: "ask", bash: "ask", mcp: "ask", skills: "ask", special: "ask" },
  tools: { read: "allow", write: "deny" },
  bash: { "git *": "ask" },
  mcp: {},
  skills: {},
  special: { doom_loop: "deny" },
};

export function runPolicyVersionTests(): void {
  const cases: Array<{ name: string; run: () => void }> = [
    {
      name: "computePolicyVersion is stable for identical policies regardless of key order",
      run: () => {
        const reordered: GlobalPermissionConfig = {
          defaultPolicy: { special: "ask", skills: "ask", mcp: "ask", bash: "ask", tools: "ask" },
          special: { doom_loop: "deny" },
          bash: { "git *": "ask" },
          mcp: {},
          skills: {},
          tools: { write: "deny", read: "allow" },
        };
        assert.equal(computePolicyVersion(basePolicy), computePolicyVersion(reordered));
      },
    },
    {
      name: "computePolicyVersion changes when an effective rule changes",
      run: () => {
        const mutated: GlobalPermissionConfig = {
          ...basePolicy,
          tools: { read: "allow", write: "allow" },
        };
        assert.notEqual(computePolicyVersion(basePolicy), computePolicyVersion(mutated));
      },
    },
    {
      name: "computePolicyVersion changes when defaultPolicy changes",
      run: () => {
        const mutated: GlobalPermissionConfig = {
          ...basePolicy,
          defaultPolicy: { tools: "deny", bash: "ask", mcp: "ask", skills: "ask", special: "ask" },
        };
        assert.notEqual(computePolicyVersion(basePolicy), computePolicyVersion(mutated));
      },
    },
    {
      name: "toCanonicalPolicy sorts rule maps by key",
      run: () => {
        const canonical = toCanonicalPolicy(basePolicy);
        assert.deepEqual(Object.keys(canonical.tools), ["read", "write"]);
        assert.deepEqual(Object.keys(canonical.special), ["doom_loop"]);
      },
    },
    {
      name: "toCanonicalPolicy drops non-permission values",
      run: () => {
        const noisy: GlobalPermissionConfig = {
          ...basePolicy,
          tools: { read: "allow", write: "deny", bogus: "not-a-state" as never },
        };
        const canonical = toCanonicalPolicy(noisy);
        assert.deepEqual(canonical.tools, { read: "allow", write: "deny" });
      },
    },
    {
      name: "diffPolicies reports added, removed, and changed rules",
      run: () => {
        const next: GlobalPermissionConfig = {
          ...basePolicy,
          tools: { read: "allow", write: "allow", grep: "deny" },
          bash: {},
        };
        const diff = diffPolicies(basePolicy, next);
        assert.deepEqual(diff.added, ["tools.grep = deny"]);
        assert.deepEqual(diff.removed, ["bash.git * = ask"]);
        assert.deepEqual(diff.changed, ["tools.write: deny -> allow"]);
      },
    },
    {
      name: "diffPolicies is empty for identical policies",
      run: () => {
        const diff = diffPolicies(basePolicy, basePolicy);
        assert.deepEqual(diff.added, []);
        assert.deepEqual(diff.removed, []);
        assert.deepEqual(diff.changed, []);
      },
    },
  ];

  for (const testCase of cases) {
    assert.doesNotThrow(() => testCase.run(), testCase.name);
    console.log(`[PASS] ${testCase.name}`);
  }
}

runPolicyVersionTests();
console.log("policy-version tests passed.");
