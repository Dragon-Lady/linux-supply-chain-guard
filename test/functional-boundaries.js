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


test("PHP readiness integrates with the default report and CLI exit precedence", t => {
  const { root, home } = fixture(t);
  const status = path.join(root, "var/lib/dpkg/status");
  fs.mkdirSync(path.dirname(status), { recursive: true });
  fs.writeFileSync(status, "Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.35-1\n\n");
  let result = run(root, home);
  assert.equal(result.status, 1, result.stderr);
  let report = JSON.parse(result.stdout);
  assert.equal(report.phpReadiness.patchStatus, "unknown");
  assert(report.findings.some(x => x.id === "php-readiness-installed-package"));
  const composer = path.join(root, "srv/app/composer.json");
  fs.mkdirSync(path.dirname(composer), { recursive: true });
  fs.writeFileSync(composer, "broken");
  report = scanHost({ targetRoot: root, homePath: home });
  assert.equal(report.coverage.complete, false);
  assert(report.coverage.inspectionFailures.includes("php-readiness-incomplete"));
  result = run(root, home, []);
  assert.equal(result.status, 3, result.stderr);
  assert.match(result.stdout, /PHP readiness: observed; patch status UNKNOWN/);
  assert.match(result.stdout, /PHP upstream fixes: 8\.2\.35, 8\.3\.36, 8\.4\.27, 8\.5\.12/);
  assert.match(result.stdout, /upstream version below 8\.3\.36; vendor backport status unverified/);
  fs.writeFileSync(path.join(home, "package.json"), '{"dependencies":{"terminal-logger-utils":"1.0.0"}}');
  assert.equal(run(root, home).status, 2);
});

test("explicit symlinked roots preserve PHP CLI inventory and exit status", t => {
  const { root, home } = fixture(t);
  fs.mkdirSync(path.join(root, "etc"));
  fs.writeFileSync(path.join(root, "etc/os-release"), "ID=debian\nVERSION_ID=12\n");
  const alias = path.join(root, "selected-root");
  fs.symlinkSync(root, alias);
  const linkedHome = path.join(alias, path.relative(root, home));
  assert.equal(run(alias, linkedHome).status, 0);
  const status = path.join(root, "var/lib/dpkg/status");
  fs.mkdirSync(path.dirname(status), { recursive: true });
  fs.writeFileSync(status, "Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.35-1\n\n");
  const result = run(alias, linkedHome);
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.coverage.complete, true);
  assert.equal(report.phpReadiness.coverage.complete, true);
  assert.equal(report.phpReadiness.records[0].name, "php8.3-fpm");
});

test("web configuration checks run by default with unknown runtime exposure", t => {
  const { root, home } = fixture(t);
  fs.mkdirSync(path.join(root, "etc"));
  fs.writeFileSync(path.join(root, "etc/os-release"), "ID=debian\nVERSION_ID=12\n");
  fs.writeFileSync(path.join(root, "etc/redis.conf"), "bind 0.0.0.0\nprotected-mode no\n");
  const result = run(root, home);
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert(report.findings.some(x => x.id === "web-store-redis-protection-disabled"));
  assert.equal(report.webExposure.runtimeExposure, "unknown");
  assert.match(run(root, home, []).stdout, /Web configuration: runtime exposure UNKNOWN/);
});

test("CLI reports incomplete coverage when proc descriptor access is unavailable", t => {
  const { root, home } = fixture(t);
  fs.mkdirSync(path.join(root, "etc"));
  fs.writeFileSync(path.join(root, "etc/os-release"), "ID=debian\nVERSION_ID=12\n");
  fs.writeFileSync(path.join(root, "etc/redis.conf"), "protected-mode no\n");
  const preload = path.join(root, "missing-proc.cjs");
  fs.writeFileSync(preload, `
    const fs = require("node:fs");
    for (const name of ["openSync", "statSync", "lstatSync", "opendirSync"]) {
      const original = fs[name];
      fs[name] = (file, ...args) => {
        if (String(file).startsWith("/proc/self/fd/"))
          throw Object.assign(new Error("private fixture error details"), { code: "ENOENT" });
        return original(file, ...args);
      };
    }
  `);
  for (const extra of [["--json"], []]) {
    const result = runCLI(process["exec" + "Path"], ["--require", preload, CLI, root, "--home", home, ...extra],
      { encoding: "utf8", timeout: 30000 });
    assert.ifError(result.error);
    assert.equal(result.status, 3, result.stderr);
    if (extra.length) {
      const report = JSON.parse(result.stdout);
      assert.equal(report.coverage.complete, false);
      assert.equal(report.webExposure.coverage.complete, false);
      assert.equal(report.summary.incomplete, true);
      assert(report.coverage.inspectionFailures.includes("web-exposure-incomplete"));
      assert(!JSON.stringify(report.webExposure).includes("private fixture error details"));
    } else assert.match(result.stdout, /Coverage: INCOMPLETE/);
  }
});

test("CLI can create a private report and compare a selected webroot with that report", t => {
  const { root, home } = fixture(t), webroot = path.join(root, "site"), saved = path.join(root, "baseline.json");
  fs.mkdirSync(path.join(root, "etc"));
  fs.writeFileSync(path.join(root, "etc/os-release"), "ID=debian\nVERSION_ID=12\n");
  fs.mkdirSync(webroot); fs.writeFileSync(path.join(webroot, "index.php"), "known version");
  const first = run(root, home, ["--webroot", webroot, "--json", "--report", saved]);
  assert.equal(first.status, 1, first.stderr);
  assert.equal(fs.statSync(saved).mode & 0o777, 0o600);
  const same = run(root, home, ["--webroot", webroot, "--web-baseline", saved, "--json"]);
  assert.equal(same.status, 0, same.stderr);
  assert.equal(JSON.parse(same.stdout).webExposure.comparison, "matched");
  fs.writeFileSync(path.join(webroot, ".user.ini"), "inert new configuration");
  const changed = run(root, home, ["--webroot", webroot, "--web-baseline", saved, "--json"]);
  assert.equal(changed.status, 1, changed.stderr);
  assert.equal(JSON.parse(changed.stdout).webExposure.comparison, "changed");
});

test("web inspection gaps affect CLI coverage and preserve critical-finding precedence", t => {
  const { root, home } = fixture(t), file = path.join(root, "etc/redis.conf");
  fs.mkdirSync(path.dirname(file)); fs.writeFileSync(file, "include /external/config\n");
  let result = run(root, home);
  assert.equal(result.status, 3, result.stderr);
  assert(JSON.parse(result.stdout).coverage.inspectionFailures.includes("web-exposure-incomplete"));
  fs.writeFileSync(path.join(home, "package.json"), '{"dependencies":{"terminal-logger-utils":"1.0.0"}}');
  result = run(root, home);
  assert.equal(result.status, 2, result.stderr);
});

test("web CLI options reject missing values, outside roots and baseline without webroot", t => {
  const { root, home } = fixture(t);
  for (const args of [["--webroot"], ["--web-compose"], ["--web-baseline"], ["--webroot", "--json"],
    ["--webroot", os.tmpdir()], ["--web-baseline", "absent.json"],
    ["--web-baseline", "first.json", "--web-baseline", "second.json"]]) {
    assert.equal(run(root, home, args).status, 64, JSON.stringify(args));
  }
});
