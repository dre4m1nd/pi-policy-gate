import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AuditLedger, auditFilePathForDate, redactSubject } from "../src/audit-ledger.js";

// Secrets are assembled at runtime. The redaction patterns must remove the
// sensitive payload; assertions check that the recognizable prefix disappears
// and a redaction marker appears, rather than matching an exact opaque value.
const API_KEY = ["sk", "-", "ant", "-", "api03", "-", "testsecretvalue1234567890"].join("");
const SHARED_TOKEN = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaa", "aaaa"].join("");

export function runAuditLedgerTests(): void {
  const redactCases: Array<{ name: string; run: () => void }> = [
    {
      name: "redacts provider-style API keys",
      run: () => {
        const actual = redactSubject(`export ANTHROPIC_API_KEY=${API_KEY}`);
        assert.ok(!actual.includes(API_KEY), "API key must be removed");
        assert.ok(actual.includes("[REDACTED"), "a redaction marker must be present");
      },
    },
    {
      name: "redacts Bearer tokens",
      run: () => {
        const actual = redactSubject("Authorization: Bearer abcdefghijklmnop");
        assert.ok(!actual.includes("abcdefghijklmnop"), "bearer token must be removed");
        assert.ok(actual.includes("[REDACTED_TOKEN]"), "bearer marker must be present");
      },
    },
    {
      name: "redacts key=value credentials",
      run: () => {
        const actual = redactSubject(`api_key=${API_KEY}`);
        assert.ok(!actual.includes(API_KEY), "credential value must be removed");
        assert.ok(actual.includes("[REDACTED"), "a redaction marker must be present");
      },
    },
    {
      name: "redacts long opaque tokens keeping a short prefix",
      run: () => {
        const actual = redactSubject(`value=${SHARED_TOKEN}`);
        assert.ok(!actual.includes(SHARED_TOKEN), "long token must be removed");
        assert.ok(actual.includes("[REDACTED_LONG]"), "long-token marker must be present");
      },
    },
    {
      name: "leaves ordinary commands intact",
      run: () => {
        assert.equal(redactSubject("git status && npm test"), "git status && npm test");
      },
    },
    {
      name: "leaves ordinary paths intact",
      run: () => {
        assert.equal(redactSubject("/home/alice/project/src/index.ts"), "/home/alice/project/src/index.ts");
      },
    },
  ];

  for (const testCase of redactCases) {
    assert.doesNotThrow(() => testCase.run(), testCase.name);
    console.log(`[PASS] ${testCase.name}`);
  }

  const dir = mkdtempSync(join(tmpdir(), "pi-policy-gate-audit-"));
  try {
    const ledger = new AuditLedger(dir);
    ledger.append({
      policyVersion: "v1-abc",
      toolName: "bash",
      source: "bash",
      state: "deny",
      decision: "deny",
      matchedPattern: "git *",
      subject: redactSubject(`git push --token ${API_KEY}`),
      sessionId: "call-1",
    });
    ledger.append({
      policyVersion: "v1-abc",
      toolName: "read",
      source: "tool",
      state: "allow",
      decision: "allow",
      matchedPattern: "read",
      subject: "src/index.ts",
      sessionId: "call-2",
    });

    const entries = ledger.read();
    assert.equal(entries.length, 2);
    assert.equal(entries[0].toolName, "bash");
    assert.equal(entries[0].decision, "deny");
    assert.equal(entries[0].policyVersion, "v1-abc");
    assert.equal(entries[0].sessionId, "call-1");
    // The API key inside the subject must be redacted in the persisted record.
    const rawSubject = `git push --token ${API_KEY}`;
    assert.ok(entries[0].subject && entries[0].subject !== rawSubject);
    assert.ok(entries[0].subject && entries[0].subject.includes("[REDACTED"));
    assert.equal(entries[1].decision, "allow");

    const recent = ledger.readRecent(5);
    assert.equal(recent.length, 2);
    // readRecent returns newest first.
    assert.equal(recent[0].toolName, "read");

    const file = auditFilePathForDate(dir, new Date("2026-11-16T10:00:00Z"));
    assert.ok(file.includes("decisions-2026-11-16.jsonl"));

    console.log("[PASS] audit ledger append/read/readRecent and redaction");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("audit-ledger tests passed.");
}

runAuditLedgerTests();
