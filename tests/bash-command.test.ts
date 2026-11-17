import assert from "node:assert/strict";

import { BashFilter } from "../src/bash-filter.js";
import { compileCommandPattern, isCommandRule } from "../src/bash-command.js";

type Case = { name: string; run: () => void };

export function runBashCommandTests(): void {
  const cases: Case[] = [
    {
      name: "isCommandRule detects the cmd: marker",
      run: () => {
        assert.equal(isCommandRule("cmd:git push"), true);
        assert.equal(isCommandRule("git push"), false);
        assert.equal(isCommandRule("git *"), false);
      },
    },
    {
      name: "cmd rule matches the exact command",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("git push"), true);
      },
    },
    {
      name: "cmd rule matches with arguments",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("git push --force origin main"), true);
        assert.equal(pattern.regex.test("git push origin feature/x"), true);
      },
    },
    {
      name: "cmd rule matches through optional environment assignments",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("GIT_TRACE=1 git push"), true);
        assert.equal(pattern.regex.test("A=1 B=2 git push --force"), true);
      },
    },
    {
      name: "cmd rule matches an executable path",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("/usr/bin/git push"), true);
        assert.equal(pattern.regex.test("./bin/git push origin main"), true);
      },
    },
    {
      name: "cmd rule matches an optional .exe suffix",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("git.exe push"), true);
      },
    },
    {
      name: "cmd rule matches before a shell separator",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("git push; rm -rf /"), true);
        assert.equal(pattern.regex.test("git push && echo done"), true);
        assert.equal(pattern.regex.test("git push | tee log"), true);
      },
    },
    {
      name: "cmd rule does not match a different subcommand",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("git status"), false);
        assert.equal(pattern.regex.test("git pull"), false);
      },
    },
    {
      name: "cmd rule does not match a longer token (token boundary)",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("git pushx"), false);
        assert.equal(pattern.regex.test("git pushy --force"), false);
      },
    },
    {
      name: "cmd rule does not match a non-leading occurrence",
      run: () => {
        const pattern = compileCommandPattern("cmd:git push", "deny");
        assert.equal(pattern.regex.test("echo git push"), false);
      },
    },
    {
      name: "non-cmd patterns keep wildcard semantics",
      run: () => {
        const pattern = compileCommandPattern("git *", "ask");
        assert.equal(pattern.regex.test("git push"), true);
        const exact = compileCommandPattern("git status", "allow");
        assert.equal(exact.regex.test("git status"), true);
        assert.equal(exact.regex.test("git status --short"), false, "exact non-cmd pattern remains exact");
      },
    },
    {
      name: "BashFilter applies cmd rules with last-match-wins",
      run: () => {
        const filter = new BashFilter(
          {
            "git *": "ask",
            "cmd:git push": "deny",
            "cmd:git status": "allow",
          },
          "ask",
        );
        assert.equal(filter.check("git push --force").state, "deny");
        assert.equal(filter.check("git push --force").matchedPattern, "cmd:git push");
        assert.equal(filter.check("git status --short").state, "allow");
        assert.equal(filter.check("git log").state, "ask");
        assert.equal(filter.check("git log").matchedPattern, "git *");
      },
    },
    {
      name: "BashFilter last-match-wins lets a later wildcard override an earlier cmd rule",
      run: () => {
        const filter = new BashFilter(
          {
            "cmd:git push": "deny",
            "git *": "ask",
          },
          "ask",
        );
        // The wildcard is declared after the cmd rule, so it wins.
        assert.equal(filter.check("git push --force").state, "ask");
      },
    },
  ];

  for (const testCase of cases) {
    assert.doesNotThrow(() => testCase.run(), testCase.name);
    console.log(`[PASS] ${testCase.name}`);
  }

  console.log("bash-command tests passed.");
}

runBashCommandTests();
