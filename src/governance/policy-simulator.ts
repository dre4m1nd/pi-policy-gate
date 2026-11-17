import { computePolicyVersion, toCanonicalPolicy } from "./policy-version.js";
import { evaluateToolCall, type PipelineDecision } from "./policy-pipeline.js";
import type { PermissionManager } from "../core/permission-manager.js"
import type { PermissionState } from "../core/types.js"

/**
 * Policy simulator and regression harness.
 *
 * The simulator runs a fixed corpus of tool-call samples against an effective
 * policy and reports, for every sample, the decision the gate would take. This
 * turns the permission policy from a runtime-only concern into something that
 * can be validated offline:
 *
 *   - decision matrix — every sample's actual vs expected decision
 *   - rule coverage   — how often each policy rule is exercised
 *   - dead rules      — rules that never matched any sample
 *   - decision diff   — which samples changed decision between two policies
 *
 * It reuses the exact same pure pipeline as the live gate, so a passing
 * simulation means the live gate will agree with the expected decisions.
 */

export type SimulationSample = {
  toolName: string;
  input: unknown;
  agentName?: string;
  expected: PermissionState;
  note?: string;
};

export type SampleResult = {
  index: number;
  toolName: string;
  note?: string;
  expected: PermissionState;
  actual: PermissionState;
  decision: PipelineDecision["decision"];
  matchedPattern?: string;
  source: PipelineDecision["source"];
  policyVersion: string;
  passed: boolean;
};

export type RuleHit = {
  category: string;
  pattern: string;
  state: PermissionState;
  hits: number;
};

export type SimulationReport = {
  policyVersion: string;
  samples: SampleResult[];
  ruleCoverage: RuleHit[];
  deadRules: RuleHit[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    coverage: number;
  };
};

function collectPolicyRules(manager: PermissionManager, agentName?: string): RuleHit[] {
  const canonical = toCanonicalPolicy(manager.getEffectivePolicy(agentName));
  const hits: RuleHit[] = [];
  for (const category of ["defaultPolicy", "tools", "bash", "mcp", "skills", "special"]) {
    const rules = canonical[category as keyof typeof canonical];
    for (const [pattern, state] of Object.entries(rules)) {
      hits.push({ category, pattern, state, hits: 0 });
    }
  }
  return hits;
}

/**
 * Run a corpus against a policy. Returns a full report including per-sample
 * results, rule coverage, and detected dead rules.
 */
export function runSimulation(
  manager: PermissionManager,
  samples: SimulationSample[],
  agentName?: string,
): SimulationReport {
  const policyVersion = computePolicyVersion(manager.getEffectivePolicy(agentName));

  const ruleHits = new Map<string, RuleHit>();
  for (const rule of collectPolicyRules(manager, agentName)) {
    ruleHits.set(`${rule.category}\u0000${rule.pattern}`, rule);
  }

  const sourceToCategory: Record<PipelineDecision["source"], string> = {
    tool: "tools",
    bash: "bash",
    mcp: "mcp",
    skill: "skills",
    special: "special",
    default: "defaultPolicy",
  };

  const sampleResults: SampleResult[] = samples.map((sample, index) => {
    const decision = evaluateToolCall(manager, sample.toolName, sample.input, sample.agentName ?? agentName);
    const category = sourceToCategory[decision.source];
    const key = `${category}\u0000${decision.matchedPattern ?? ""}`;
    const rule = ruleHits.get(key);
    if (rule) {
      rule.hits += 1;
    }
    return {
      index,
      toolName: sample.toolName,
      note: sample.note,
      expected: sample.expected,
      actual: decision.state,
      decision: decision.decision,
      matchedPattern: decision.matchedPattern,
      source: decision.source,
      policyVersion: decision.policyVersion,
      passed: decision.state === sample.expected,
    };
  });

  const ruleCoverage = [...ruleHits.values()];
  // defaultPolicy entries are fallback semantics, not explicit rules to be
  // exercised, so they are excluded from dead-rule detection.
  const deadRules = ruleCoverage.filter((rule) => rule.hits === 0 && rule.category !== "defaultPolicy");
  const passed = sampleResults.filter((sample) => sample.passed).length;

  return {
    policyVersion,
    samples: sampleResults,
    ruleCoverage,
    deadRules,
    summary: {
      total: sampleResults.length,
      passed,
      failed: sampleResults.length - passed,
      coverage: sampleResults.length === 0
        ? 0
        : Number((passed / sampleResults.length).toFixed(4)),
    },
  };
}

export type DecisionDiffEntry = {
  index: number;
  toolName: string;
  note?: string;
  expected: PermissionState;
  baseDecision: PermissionState;
  nextDecision: PermissionState;
  changed: boolean;
};

/**
 * Compare two simulation reports and report the samples whose decision changed
 * between the two policies. Use this to catch unintended allow/deny changes
 * when a policy is edited.
 */
export function diffDecisions(
  base: SimulationReport,
  next: SimulationReport,
): DecisionDiffEntry[] {
  return base.samples.map((baseSample, index) => {
    const nextSample = next.samples[index];
    const baseDecision = baseSample.actual;
    const nextDecision = nextSample?.actual ?? baseDecision;
    return {
      index,
      toolName: baseSample.toolName,
      note: baseSample.note,
      expected: baseSample.expected,
      baseDecision,
      nextDecision,
      changed: baseDecision !== nextDecision,
    };
  });
}
