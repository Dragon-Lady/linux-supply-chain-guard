"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { scanUpdraftReview } = require("../src/updraft-review");
const { spawnSync: runFixture } = require(["child", "process"].join("_"));
const CLI = path.join(__dirname, "..", "bin", "linux-supply-chain-guard.js");
const marker = ["Small maintenance toolkit:", "keeps option storage tidy."].join(" ");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "updraft-review-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const site = path.join(root, "site"), home = path.join(root, "home");
  fs.mkdirSync(path.join(site, "wp-content", "plugins"), { recursive: true });
  fs.mkdirSync(home);
  const put = (name, data) => {
    const file = path.join(root, name); fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, data); return file;
  };
  const scan = (options = {}) => scanUpdraftReview({ targetRoot: root, ...options });
  const cli = args => {
    const r = runFixture(process["exec" + "Path"], [CLI, root, "--home", home, ...args], { encoding: "utf8", timeout: 30000 });
    assert.ifError(r.error); return r;
  };
  return { root, site, put, scan, cli };
}
const ids = r => r.findings.map(x => x.id);
const evidence = () => ({ schema: 1, keys: { cloud: 0, selfHosted: 0, unknown: 0 }, users: [], optionNames: [] });

test("opt-in stays idle by default; clean selected files never establish site safety", t => {
  const f = fixture(t);
  assert.equal(f.scan().requested, false);
  f.put("site/wp-content/plugins/ordinary/main.php", "<?php /* ordinary inert fixture */");
  const r = f.scan({ wordpressRoots: [f.site] });
  assert.deepEqual(ids(r), []);
  assert.equal(r.layers.files, "inspected");
  assert.equal(r.layers.database, "not-selected");
  assert.equal(r.layers.logs, "not-selected");
  assert.equal(r.compromiseStatus, "unknown");
});
for (const directory of ["plugins/renamed/nested", "mu-plugins", "upgrade/unpacked/vendor"])
  test("published markers found under " + directory, t => {
    const f = fixture(t);
    const file = f.put("site/wp-content/" + directory + "/fixture.php", marker + " PRIVATE_SENTINEL");
    const before = fs.readFileSync(file);
    const r = f.scan({ wordpressRoots: [f.site] });
    assert(ids(r).includes("updraft-published-plugin-marker"));
    assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
    assert.deepEqual(fs.readFileSync(file), before);
  });
test("renamed working variants, URL login and hiding patterns have distinct review findings", t => {
  const f = fixture(t);
  f.put("site/wp-content/plugins/a/a.inc", "_sync_token hash_equals( wp_set_auth_cookie(");
  f.put("site/wp-content/plugins/b/b.php", "pre_user_query pre_count_users wp_set_auth_cookie(");
  f.put("site/wp-content/plugins/c/c.PHP", "$_GET hash_equals('" + "A".repeat(32) + "' wp_set_auth_cookie(");
  f.put("site/wp-content/plugins/d/d.phtml", "$_GET wp_set_auth_cookie(");
  f.put("site/wp-content/plugins/e/e.php", "add_filter('all_plugins' plugin_basename(__FILE__) unset(");
  const r = f.scan({ wordpressRoots: [f.site] });
  assert.equal(r.findings.filter(x => x.id === "updraft-backdoor-code-markers").length, 3);
  assert(ids(r).includes("updraft-url-login-review"));
  assert(ids(r).includes("updraft-plugin-hiding-review"));
  assert.equal(r.findings.some(x => x.severity === "critical"), false);
});
test("generic plugin name or authentication function alone does not match", t => {
  const f = fixture(t);
  f.put("site/wp-content/plugins/site-health-cache/test.php", "Site Health Cache wp_set_auth_cookie(");
  assert.deepEqual(ids(f.scan({ wordpressRoots: [f.site] })), []);
});
test("logs match separate signals without leaking query values or claiming success", t => {
  const f = fixture(t), secret = "Z".repeat(32);
  const file = f.put("access.log", "probe.central.updraftplus.com\nCommand received: plugin.upload_plugin\n"
    + '"WordPress/6.4; class-udrpc.php"\nGET /?_abc12=' + secret + ' HTTP/1.1\nPRIVATE_SENTINEL');
  const r = f.scan({ updraftLogs: [file] });
  for (const id of ["log-probe-marker", "log-plugin-command", "log-client-marker", "log-trigger-shape"])
    assert(ids(r).includes("updraft-" + id));
  assert(!JSON.stringify(r).includes(secret));
  assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
  assert.equal(r.compromiseStatus, "unknown");
  f.put("access.log", '"WordPress/6.8.5; class-udrpc.php/2.0; https://teamupdraft.com"\nGET /?_abc12=short HTTP/1.1');
  assert.deepEqual(ids(f.scan({ updraftLogs: [file] })), []);
});
test("sanitized evidence checks capabilities, key classes and option names without exposing values", t => {
  const f = fixture(t), data = evidence();
  data.keys.cloud = 1;
  data.users = [{ id: 19, roles: ["editor"], capabilities: ["manage_options", "install_plugins"] },
    { id: 20, roles: ["administrator"], capabilities: ["manage_options"] }];
  data.optionNames = ["fixture_sync_token"];
  const file = f.put("evidence.json", JSON.stringify(data));
  const r = f.scan({ wordpressEvidence: file });
  for (const id of ["connection-keys-review", "nonadmin-capabilities", "token-option-review"])
    assert(ids(r).includes("updraft-" + id));
  assert.equal(r.findings.filter(x => x.id === "updraft-nonadmin-capabilities").length, 1);
  assert(r.findings.some(x => x.evidence.endsWith("#user-id=19")));
  assert(!JSON.stringify(r).includes("fixture_sync_token"));
  data.keys = { cloud: 0, selfHosted: 4, unknown: 0 }; data.users = []; data.optionNames = [];
  f.put("evidence.json", JSON.stringify(data));
  assert.deepEqual(ids(f.scan({ wordpressEvidence: file })), []);
  data.keys.unknown = 1; f.put("evidence.json", JSON.stringify(data));
  assert(ids(f.scan({ wordpressEvidence: file })).includes("updraft-connection-keys-review"));
});
test("raw dumps, malformed JSON, extra secret fields and invalid capability records are incomplete", t => {
  const f = fixture(t);
  for (const input of ["{bad", "INSERT INTO users VALUES ('PRIVATE_SENTINEL');", "{}",
    JSON.stringify({ ...evidence(), privateKey: "PRIVATE_SENTINEL" }),
    JSON.stringify({ ...evidence(), users: [{ id: 1, roles: ["editor"], capabilities: { install_plugins: false } }] }),
    JSON.stringify({ ...evidence(), keys: { cloud: -1, selfHosted: 0, unknown: 0 } })]) {
    const file = f.put("evidence.json", input), r = f.scan({ wordpressEvidence: file });
    assert.equal(r.coverage.complete, false);
    assert.equal(r.layers.database, "incomplete");
    assert(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
  }
});
test("missing, binary and empty selected logs are gaps; special files and links are never followed", t => {
  const f = fixture(t);
  const binary = f.put("binary.log", Buffer.from([0, 1])), empty = f.put("empty.log", "");
  const source = f.put("outside.php", marker), linked = path.join(f.site, "wp-content/plugins/link.php");
  fs.symlinkSync(source, linked);
  for (const file of [path.join(f.root, "absent.log"), binary, empty, linked]) {
    const r = f.scan({ updraftLogs: [file] });
    assert.equal(r.coverage.complete, false);
    assert.equal(r.layers.logs, "incomplete");
    assert(!ids(r).includes("updraft-published-plugin-marker"));
  }
  assert.equal(f.scan({ wordpressRoots: [f.site] }).coverage.complete, false);
});
test("missing WordPress layout, exclusions and exhausted limits produce incomplete results", t => {
  const f = fixture(t);
  f.put("site/wp-content/plugins/a.php", marker);
  assert.equal(f.scan({ wordpressRoots: [f.root] }).coverage.complete, false);
  assert.equal(f.scan({ wordpressRoots: [f.site], excludePaths: [path.join(f.site, "wp-content/plugins")] }).coverage.complete, false);
  for (const limits of [{ fileBytes: 2 }, { bytes: 2 }, { entries: 1 }]) {
    f.put("site/wp-content/plugins/b.php", marker);
    assert.equal(f.scan({ wordpressRoots: [f.site], limits }).coverage.complete, false);
  }
});
test("missing procfs fails closed for every selected layer", t => {
  const f = fixture(t), file = f.put("evidence.json", JSON.stringify(evidence()));
  const original = fs.statSync;
  fs.statSync = (p, ...args) => {
    if (typeof p === "string" && p.startsWith("/proc/self/fd/")) throw Object.assign(new Error("fixture"), { code: "ENOENT" });
    return original(p, ...args);
  };
  try {
    const r = f.scan({ wordpressRoots: [f.site], updraftLogs: [file], wordpressEvidence: file });
    assert.equal(r.coverage.complete, false);
    assert.deepEqual(Object.values(r.layers), ["incomplete", "incomplete", "incomplete"]);
  } finally { fs.statSync = original; }
});
test("FIFO input is rejected without blocking and unreadable PHP files are gaps", t => {
  const f = fixture(t), fifo = path.join(f.root, "events.log");
  const made = runFixture("mkfifo", [fifo], { encoding: "utf8", timeout: 1000 });
  assert.ifError(made.error); assert.equal(made.status, 0);
  assert.equal(f.scan({ updraftLogs: [fifo] }).coverage.complete, false);
  if (process.getuid && process.getuid() !== 0) {
    const file = f.put("site/wp-content/plugins/private.php", marker);
    fs.chmodSync(file, 0);
    try { assert.equal(f.scan({ wordpressRoots: [f.site] }).coverage.complete, false); }
    finally { fs.chmodSync(file, 0o600); }
  }
});
test("finding limits and duplicate user IDs cannot silently produce complete evidence", t => {
  const f = fixture(t), data = evidence();
  data.users = [1, 2, 3].map(id => ({ id, roles: ["editor"], capabilities: ["install_plugins"] }));
  const file = f.put("evidence.json", JSON.stringify(data));
  const limited = f.scan({ wordpressEvidence: file, limits: { findings: 1 } });
  assert.equal(limited.coverage.complete, false);
  assert.equal(limited.layers.database, "incomplete");
  data.users[2].id = 1; f.put("evidence.json", JSON.stringify(data));
  assert.equal(f.scan({ wordpressEvidence: file }).layers.database, "incomplete");
});
test("CLI integrates findings, incomplete exit status, private reports and usage errors", t => {
  const f = fixture(t), suspicious = f.put("site/wp-content/plugins/fixture.php", marker);
  const output = path.join(f.root, "report.json");
  const found = f.cli(["--wordpress-root", f.site, "--json", "--report", output]);
  assert.equal(found.status, 1, found.stderr);
  assert(ids(JSON.parse(found.stdout).updraftReview).includes("updraft-published-plugin-marker"));
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  fs.unlinkSync(suspicious);
  const incomplete = f.cli(["--updraft-log", path.join(f.root, "absent"), "--json"]);
  assert.equal(incomplete.status, 3, incomplete.stderr);
  assert(JSON.parse(incomplete.stdout).coverage.inspectionFailures.includes("updraft-review-incomplete"));
  for (const args of [["--wordpress-root"], ["--updraft-log", "--json"], ["--wordpress-evidence"],
    ["--wordpress-root", os.tmpdir()], ["--wordpress-evidence", "a", "--wordpress-evidence", "b"]])
    assert.equal(f.cli(args).status, 64);
  assert.match(f.cli(["--wordpress-root", f.site]).stdout, /UpdraftCentral: compromise UNKNOWN/);
});
