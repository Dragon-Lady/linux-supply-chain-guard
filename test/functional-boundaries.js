"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const { scanHost } = require("../src/checker");
const CLI = path.join(__dirname, "..", "bin", "linux-supply-chain-guard.js");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "host-coverage-"));
  const home = path.join(root, "home", "fixture");
  fs.mkdirSync(home, { recursive: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home };
}
function run(root, home, extra = ["--json"]) {
  const result = runCLI(process["exec" + "Path"], [CLI, root, "--home", home, ...extra], { encoding: "utf8", timeout: 30000 });
  assert.ifError(result.error);
  return result;
}
test("explicit missing or non-directory roots are errors", (t) => {
  const { root, home } = fixture(t);
  const file = path.join(home, "ordinary.txt");
  fs.writeFileSync(file, "ordinary fixture");
  for (const target of [path.join(root, "absent"), file]) {
    assert.throws(() => scanHost({ targetRoot: target, homePath: home }));
    const result = run(target, home);
    assert.equal(result.status, 64);
    assert.equal(result.stdout, "");
  }
});
test("invalid path options cannot silently change scope", (t) => {
  const { root, home } = fixture(t);
  for (const args of [["--report"], ["--home"], ["--report", "--json"], ["--home", "--json"], [root]]) {
    assert.equal(run(root, home, args).status, 64);
  }
});
test("unreadable discovered manifest makes the whole report incomplete", {
  skip: !process.getuid || process.getuid() === 0,
}, (t) => {
  const { root, home } = fixture(t);
  const file = path.join(home, "package.json");
  fs.writeFileSync(file, '{"name":"ordinary-fixture","version":"1.0.0"}');
  fs.chmodSync(file, 0);
  try {
    const result = run(root, home);
    assert.equal(result.status, 3, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.coverage.complete, false);
    assert.equal(report.summary.incomplete, true);
    assert(report.coverage.unreadablePaths > 0);
    assert(report.coverage.inspectionFailures.includes("tensorlake-coverage-incomplete"));
    assert.match(run(root, home, []).stdout, /Coverage: INCOMPLETE/);
  } finally { fs.chmodSync(file, 0o600); }
  const repaired = scanHost({ targetRoot: root, homePath: home });
  assert.equal(repaired.coverage.complete, true, "coverage state must reset between scans");
});
test("read failures outside manifest checks are counted without leaking content", (t) => {
  const { root, home } = fixture(t);
  const file = path.join(home, "ordinary.txt");
  fs.writeFileSync(file, "fixture source is private");
  const original = fs.readFileSync;
  fs.readFileSync = (input, ...args) => {
    if (input === file) throw Object.assign(new Error("private fixture error details"), { code: "EACCES" });
    return original(input, ...args);
  };
  try {
    const report = scanHost({ targetRoot: root, homePath: home });
    assert.equal(report.coverage.complete, false);
    assert(report.coverage.unreadableSamples.includes(file));
    assert(!JSON.stringify(report).includes("private fixture error details"));
    assert(!JSON.stringify(report).includes("fixture source is private"));
  } finally { fs.readFileSync = original; }
});
for (const kind of ["malformed-manifest", "oversized-artifact"]) {
  test(kind + " is incomplete in both API and CLI", (t) => {
    const { root, home } = fixture(t);
    if (kind === "malformed-manifest") fs.writeFileSync(path.join(home, "package.json"), "{broken");
    else {
      const fd = fs.openSync(path.join(home, "archive.vsix"), "wx");
      fs.ftruncateSync(fd, 100 * 1024 * 1024 + 1);
      fs.closeSync(fd);
    }
    const report = scanHost({ targetRoot: root, homePath: home });
    assert.equal(report.summary.incomplete, true);
    assert(report.coverage.inspectionFailures.includes("glassworm-artifact-not-inspected"));
    assert.equal(run(root, home).status, 3);
    assert.match(run(root, home, []).stdout, /Coverage: INCOMPLETE/);
  });
}
test("discovery budgets are represented in top-level coverage", (t) => {
  const { root, home } = fixture(t);
  const file = path.join(home, "package.json");
  fs.writeFileSync(file, '{"name":"ordinary-fixture","version":"1.0.0"}');
  const original = fs.readdirSync;
  const entry = { name: "package.json", isDirectory: () => false, isFile: () => true };
  fs.readdirSync = (input, ...args) => input === home ? Array(25000).fill(entry) : original(input, ...args);
  try {
    const report = scanHost({ targetRoot: root, homePath: home });
    assert.equal(report.coverage.complete, false);
    assert(report.coverage.limitedSearches > 0);
    assert.equal(report.summary.incomplete, true);
  } finally { fs.readdirSync = original; }
});
test("critical findings retain precedence over incomplete coverage", (t) => {
  const { root, home } = fixture(t);
  fs.writeFileSync(path.join(home, "package.json"), JSON.stringify({ dependencies: { "terminal-logger-utils": "1.0.0" } }));
  const bad = path.join(home, "broken");
  fs.mkdirSync(bad);
  fs.writeFileSync(path.join(bad, "package.json"), "{broken");
  const result = run(root, home);
  assert.equal(result.status, 2);
  const report = JSON.parse(result.stdout);
  assert.equal(report.summary.incomplete, true);
  assert(report.summary.critical > 0);
});
test("missing optional host paths do not make an empty mounted root incomplete", (t) => {
  const { root, home } = fixture(t);
  const report = scanHost({ targetRoot: root, homePath: home });
  assert.equal(report.coverage.complete, true);
  assert.match(report.coverage.scope, /enabled rule lanes/);
  assert.equal(report.coverage.unreadablePaths, 0);
});

