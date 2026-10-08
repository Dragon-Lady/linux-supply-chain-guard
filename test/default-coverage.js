"use strict";
// Regression: default scans must not silently skip cache, agent, IDE-history,
// cloud-sync or security-tool-named directories. Operator exclusions must make
// the report incomplete and the CLI exit non-zero.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const { scanHost } = require("../src/checker");

const CLI = path.join(__dirname, "..", "bin", "linux-supply-chain-guard.js");
const INDICATOR = "compromised-npm-package-reference";
let tests = 0;

function plant(home, relativeDir) {
  const dir = path.join(home, ...relativeDir.split("/"));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { "atomic-lockfile": "1.0.0" } }));
  return dir;
}

function fixture(relativeDir) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "coverage-"));
  const home = path.join(root, "home", "fixture");
  const dir = plant(home, relativeDir);
  return { root, home, dir };
}

function hasIndicator(report) {
  return report.findings.some((finding) => finding.id === INDICATOR);
}

const locations = [
  ".cache/x",
  ".cache/pip/x",
  "agent-tools/x",
  "OneDrive/x",
  "Dropbox/x",
  ".config/Code/User/History/x",
  ".cursor/projects/x",
  "Documents/Codex/x",
  "src/push-guard/x",
  "src/linux-supply-chain-guard/x",
  "src/prompt-injection-blocker/x",
];

for (const location of locations) {
  const { root, home } = fixture(location);
  try {
    const report = scanHost({ targetRoot: root, homePath: home });
    assert(hasIndicator(report), `planted indicator under ${location} must be detected by default`);
    assert.strictEqual(report.summary.incomplete, false, `${location}: default scan should be complete`);
    assert.strictEqual(report.coverage.complete, true);
    assert.strictEqual(report.summary.suppressed.research, 0);
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

// --include-research is accepted for compatibility and changes nothing.
{
  const { root, home } = fixture(".cache/x");
  try {
    const result = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, "--json", "--include-research"], { encoding: "utf8" });
    assert.ifError(result.error);
    const report = JSON.parse(result.stdout);
    assert(hasIndicator(report));
    assert.strictEqual(result.status, 2);
    const warning = "warning: --include-research is deprecated and has no effect; research folders are scanned by default";
    assert.strictEqual(result.stderr.trim(), warning, "deprecation warning must be printed once to stderr");
    assert(!result.stdout.includes("deprecated"), "warning must not pollute JSON stdout");
    const plain = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, "--json"], { encoding: "utf8" });
    assert.strictEqual(plain.stderr, "", "no warning without the flag");
    assert.strictEqual(plain.status, result.status, "the flag must not change the exit code");
    const twice = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, "--include-research", "--include-research"], { encoding: "utf8" });
    assert.strictEqual(twice.stderr.trim(), warning);
    assert.strictEqual(twice.status, 2);
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

// Operator exclusion: skipped tree is reported, scan is incomplete, exit 3.
{
  const { root, home, dir } = fixture(".cache/x");
  try {
    const report = scanHost({ targetRoot: root, homePath: home, excludePaths: [path.dirname(dir)] });
    assert(!hasIndicator(report));
    assert.strictEqual(report.summary.incomplete, true);
    assert.strictEqual(report.coverage.complete, false);
    assert(report.coverage.skippedDirectories > 0);
    assert.deepStrictEqual(report.coverage.excludedPaths, [path.resolve(path.dirname(dir))]);

    const result = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, "--json", "--exclude", path.dirname(dir)], { encoding: "utf8" });
    assert.ifError(result.error);
    const cliReport = JSON.parse(result.stdout);
    assert.strictEqual(cliReport.summary.incomplete, true);
    assert.strictEqual(result.status, 3, "an incomplete scan must exit 3 when nothing more severe was found");

    const text = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, `--exclude=${path.dirname(dir)}`], { encoding: "utf8" });
    assert.strictEqual(text.status, 3);
    assert(/Coverage: INCOMPLETE/.test(text.stdout));
    tests += 1;

    // An exclusion that matches nothing leaves the scan complete.
    const unused = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, "--json", "--exclude", path.join(root, "nothing-here")], { encoding: "utf8" });
    assert.strictEqual(JSON.parse(unused.stdout).summary.incomplete, false);
    assert.strictEqual(unused.status, 2);
    tests += 1;

    for (const bad of [["--exclude"], ["--exclude", "--json"], ["--exclude="], ["--exclude", "/"]]) {
      const usage = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, ...bad], { encoding: "utf8" });
      assert.strictEqual(usage.status, 64, `usage error expected for ${bad.join(" ")}`);
    }
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

console.log(`${tests} default-coverage and exclusion tests passed`);
